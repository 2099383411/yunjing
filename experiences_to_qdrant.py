import json, os, asyncio, sys

os.environ['DATABASE_URL'] = 'postgresql+asyncpg://yunjing:yunjing_dev_2026@postgres:5432/yunjing'
os.environ['QDRANT_URL'] = 'http://yunjing-qdrant:6333'
os.environ['BGE_SERVICE_URL'] = 'http://yunjing-bge:8000'

sys.path.insert(0, '/root/yunjing/backend')

from app.engine.vector_store import RAGEngine

async def main():
    # Check Qdrant health first
    print('Checking Qdrant...')
    import httpx
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f'{os.environ["QDRANT_URL"]}/collections', timeout=10)
            print(f'Qdrant collections: {r.json()}')
        except Exception as e:
            print(f'Qdrant check: {e}')
    
    # Load learning data
    with open('/root/yunjing/backend/app/engine/learning_data.json') as f:
        ld = json.load(f)
    exps = ld.get('experiences', [])
    print(f'Total experiences in JSON: {len(exps)}')
    
    # Index to Qdrant
    print('Initializing RAGEngine...')
    engine = RAGEngine()
    print('Indexing experiences...')
    count = await engine.index_experience(exps)
    print(f'Indexed {count} experience vectors to Qdrant')
    
    # Verify
    stats = await engine.count()
    print(f'Final Qdrant stats: {stats}')

asyncio.run(main())
