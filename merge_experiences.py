import json, os, sys, datetime

# 1. Load new experiences
with open('/root/yunjing/experiences_new.json') as f:
    new_exps = json.load(f)

# 2. Load current learning_data
with open('/root/yunjing/backend/app/engine/learning_data.json') as f:
    ld = json.load(f)

# 3. Dedup by title
existing_titles = set(e.get('title', '') for e in ld.get('experiences', []))

added = 0
skipped = 0
for exp in new_exps:
    title = exp.get('title', '')
    if title and title not in existing_titles:
        entry = {
            'title': title,
            'hypothesis': exp.get('hypothesis', ''),
            'verification_steps': exp.get('verification_steps', []),
            'tools': exp.get('tools', []),
            'expected_outcomes': exp.get('expected_outcomes', []),
            'risk_level': exp.get('risk_level', 'medium'),
            'target_type': exp.get('target_type', 'unknown'),
            'mitigation': exp.get('mitigation', ''),
            'references': exp.get('references', []),
            'source_files': exp.get('source_files', []),
            'success_count': 0,
            'failure_count': 0,
            'last_used': None,
            'created_at': datetime.datetime.now().isoformat()
        }
        ld.setdefault('experiences', []).append(entry)
        existing_titles.add(title)
        added += 1
    else:
        skipped += 1

ld.setdefault('meta', {})['total_experiences'] = len(ld['experiences'])
ld['meta']['last_updated'] = datetime.datetime.now().isoformat()
ld['meta']['source'] = 'InternalAllTheThings'

with open('/root/yunjing/backend/app/engine/learning_data.json', 'w') as f:
    json.dump(ld, f, ensure_ascii=False, indent=2)

print(f'ADDED={added} SKIPPED={skipped} TOTAL={len(ld["experiences"])}')
