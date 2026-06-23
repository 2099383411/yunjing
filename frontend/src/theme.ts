import type { ThemeConfig } from "antd";

/** 微步风格 — 深海军蓝 + 亮蓝点缀 */
const brandTheme: ThemeConfig = {
  token: {
    colorPrimary: "#2563EB",
    colorInfo: "#2563EB",
    colorSuccess: "#10B981",
    colorWarning: "#F59E0B",
    colorError: "#EF4444",
    colorLink: "#2563EB",
    colorBgBase: "#F8FAFC",
    colorBgContainer: "#FFFFFF",
    colorBgElevated: "#FFFFFF",
    colorBgLayout: "#F1F5F9",
    colorTextBase: "#0F172A",
    colorTextSecondary: "#475569",
    colorTextTertiary: "#94A3B8",
    colorBorder: "#E2E8F0",
    colorBorderSecondary: "#CBD5E1",
    borderRadius: 8,
    fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'PingFang SC', 'Microsoft YaHei', sans-serif",
    fontSize: 14,
    controlHeight: 36,
    boxShadow: "0 1px 3px 0 rgba(0,0,0,0.04), 0 1px 2px -1px rgba(0,0,0,0.06)",
    boxShadowSecondary: "0 4px 12px rgba(0,0,0,0.08)",
  },
  components: {
    Layout: {
      headerBg: "#FFFFFF",
      bodyBg: "#F1F5F9",
      siderBg: "#0F172A",
      headerHeight: 56,
      headerPadding: "0 24px",
      colorBgHeader: "#FFFFFF",
    },
    Menu: {
      itemBg: "transparent",
      itemColor: "#CBD5E1",
      itemHoverColor: "#FFFFFF",
      itemSelectedColor: "#FFFFFF",
      itemSelectedBg: "rgba(37, 99, 235, 0.3)",
      subMenuItemBg: "#0A1628",
      popupBg: "#FFFFFF",
      itemMarginInline: 8,
      itemBorderRadius: 8,
      iconSize: 16,
      fontSize: 13,
      groupTitleColor: "#64748B",
      colorItemBgHover: "rgba(255,255,255,0.08)",
      colorItemTextHover: "#FFFFFF",
      colorItemTextActive: "#FFFFFF",
      colorItemBgActive: "rgba(37, 99, 235, 0.25)",
      colorSubItemBg: "#0A1628",
    },
    Card: {
      colorBgContainer: "#FFFFFF",
      colorBorderSecondary: "#E2E8F0",
      paddingLG: 24,
      borderRadiusLG: 12,
    },
    Input: {
      colorBgContainer: "#FFFFFF",
      colorBorder: "#CBD5E1",
      activeBorderColor: "#2563EB",
      hoverBorderColor: "#60A5FA",
      colorText: "#0F172A",
      colorTextPlaceholder: "#94A3B8",
      addonBg: "#F8FAFC",
    },
    Button: {
      colorBgContainer: "#FFFFFF",
      colorBgContainerDisabled: "#F1F5F9",
      borderColorDisabled: "#E2E8F0",
      colorTextDisabled: "#94A3B8",
      primaryShadow: "0 1px 2px 0 rgba(37,99,235,0.3)",
      defaultBorderColor: "#CBD5E1",
      defaultColor: "#0F172A",
      defaultHoverBorderColor: "#2563EB",
      defaultHoverColor: "#2563EB",
      defaultShadow: "0 1px 2px 0 rgba(0,0,0,0.04)",
    },
    Table: {
      colorBgContainer: "#FFFFFF",
      headerBg: "#F8FAFC",
      headerColor: "#475569",
      rowHoverBg: "#EFF6FF",
      borderColor: "#E2E8F0",
      headerBorderRadius: 8,
    },
    Modal: {
      contentBg: "#FFFFFF",
      headerBg: "#FFFFFF",
      titleColor: "#0F172A",
      footerBg: "#FFFFFF",
    },
    Tag: {
      defaultBg: "#EFF6FF",
      defaultColor: "#1D4ED8",
    },
    Tabs: {
      colorBgContainer: "#FFFFFF",
      inkBarColor: "#2563EB",
      itemColor: "#64748B",
      itemSelectedColor: "#2563EB",
      itemHoverColor: "#2563EB",
    },
    Progress: {
      colorBgContainer: "#E2E8F0",
      defaultColor: "#2563EB",
      remainingColor: "#E2E8F0",
    },
    Switch: {
      colorPrimary: "#2563EB",
    },
    Drawer: {
      colorBgElevated: "#FFFFFF",
    },
    Alert: {
      colorBgContainer: "#FFFFFF",
    },
    Badge: {
      colorBgContainer: "#FFFFFF",
    },
    Segmented: {
      colorBgContainer: "#F1F5F9",
      itemSelectedBg: "#FFFFFF",
      itemColor: "#475569",
      itemSelectedColor: "#2563EB",
      trackBg: "#F1F5F9",
    },
    Tooltip: {
      colorBg: "#0F172A",
      colorText: "#FFFFFF",
    },
    Timeline: {
      dotBg: "#FFFFFF",
      tailColor: "#E2E8F0",
      itemPaddingBottom: 16,
    },
    Select: {
      colorBgContainer: "#FFFFFF",
      colorBorder: "#CBD5E1",
      selectorBg: "#FFFFFF",
      multipleItemBg: "#EFF6FF",
      multipleItemBorderColor: "#BFDBFE",
      optionSelectedBg: "#EFF6FF",
      optionActiveBg: "#F8FAFC",
    },
    DatePicker: {
      colorBgContainer: "#FFFFFF",
      colorBorder: "#CBD5E1",
      activeBorderColor: "#2563EB",
      hoverBorderColor: "#60A5FA",
    },
    Checkbox: {
      colorBgContainer: "#FFFFFF",
      colorBorder: "#CBD5E1",
    },
    Radio: {
      colorBgContainer: "#FFFFFF",
      colorBorder: "#CBD5E1",
    },
    Upload: {
      colorBgContainer: "#FFFFFF",
      colorBorder: "#CBD5E1",
    },
    Collapse: {
      colorBgContainer: "#FFFFFF",
      headerBg: "#F8FAFC",
      colorBorder: "#E2E8F0",
    },
    Descriptions: {
      colorBgContainer: "#FFFFFF",
      colorBorderSecondary: "#E2E8F0",
    },
    List: {
      colorBgContainer: "#FFFFFF",
      colorBorderSecondary: "#E2E8F0",
    },
    Steps: {
      colorBgContainer: "#FFFFFF",
      colorBorder: "#E2E8F0",
      descriptionColor: "#64748B",
      navArrowColor: "#2563EB",
      waitIconColor: "#94A3B8",
      waitTitleColor: "#94A3B8",
      finishIconColor: "#2563EB",
      finishTitleColor: "#0F172A",
      processIconBg: "#2563EB",
      processIconColor: "#FFFFFF",
      processTitleColor: "#2563EB",
    },
    Statistic: {
      colorBgContainer: "#FFFFFF",
    },
    Notification: {
      colorBgContainer: "#FFFFFF",
    },
    Popconfirm: {
      colorBgContainer: "#FFFFFF",
    },
    Popover: {
      colorBgContainer: "#FFFFFF",
    },
    Result: {
      colorBgContainer: "#FFFFFF",
    },
    Skeleton: {
      colorBgContainer: "#F1F5F9",
    },
    Slider: {
      colorBgContainer: "#E2E8F0",
      railBg: "#E2E8F0",
      railHoverBg: "#CBD5E1",
      trackBg: "#2563EB",
      trackHoverBg: "#3B82F6",
      dotBorderColor: "#CBD5E1",
      dotActiveBorderColor: "#2563EB",
      handleColor: "#2563EB",
      handleActiveColor: "#3B82F6",
    },
    Spin: {
      colorBgContainer: "transparent",
    },
    Empty: {
      colorBgContainer: "transparent",
    },
    Avatar: {
      colorBgContainer: "#EFF6FF",
      colorText: "#2563EB",
    },
    Dropdown: {
      colorBgContainer: "#FFFFFF",
      colorPrimary: "#2563EB",
    },
    Breadcrumb: {
      colorBgContainer: "transparent",
      itemColor: "#64748B",
      lastItemColor: "#0F172A",
      linkColor: "#2563EB",
      separatorColor: "#94A3B8",
    },
    Pagination: {
      colorBgContainer: "#FFFFFF",
      colorBorder: "#CBD5E1",
      colorPrimary: "#2563EB",
    },
    Rate: {
      colorBgContainer: "transparent",
    },
    Image: {
      colorBgContainer: "#F1F5F9",
    },
    Calendar: {
      colorBgContainer: "#FFFFFF",
      colorBorder: "#E2E8F0",
    },
    Mentions: {
      colorBgContainer: "#FFFFFF",
      colorBorder: "#CBD5E1",
    },
    Transfer: {
      colorBgContainer: "#FFFFFF",
      colorBorder: "#CBD5E1",
    },
    Tree: {
      colorBgContainer: "#FFFFFF",
      colorBorder: "#CBD5E1",
      directoryNodeSelectedBg: "#EFF6FF",
      nodeHoverBg: "#F8FAFC",
      nodeSelectedBg: "#EFF6FF",
    },
    TreeSelect: {
      colorBgContainer: "#FFFFFF",
      colorBorder: "#CBD5E1",
    },
    Typography: {
      colorBgContainer: "transparent",
      colorText: "#0F172A",
      colorTextDescription: "#64748B",
      colorTextDisabled: "#94A3B8",
      linkColor: "#2563EB",
      linkHoverColor: "#3B82F6",
      linkActiveColor: "#1D4ED8",
    },
    Divider: {
      colorBgContainer: "transparent",
      colorBorder: "#E2E8F0",
      colorText: "#94A3B8",
    },
    Space: {
      colorBgContainer: "transparent",
    },
  },
};

export { brandTheme };
export default brandTheme;
