import type { ThemeConfig } from "antd";

/** 云镜品牌风格 — 深海蓝 + 天蓝点缀 */
const brandTheme: ThemeConfig = {
  token: {
    colorPrimary: "#0284c7",
    colorInfo: "#0284c7",
    colorSuccess: "#10B981",
    colorWarning: "#F59E0B",
    colorError: "#EF4444",
    colorLink: "#0284c7",
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
      activeBorderColor: "#0284c7",
      hoverBorderColor: "#7dd3fc",
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
      defaultHoverBorderColor: "#0284c7",
      defaultHoverColor: "#0284c7",
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
      defaultColor: "#0369a1",
    },
    Tabs: {
      colorBgContainer: "#FFFFFF",
      inkBarColor: "#0284c7",
      itemColor: "#64748B",
      itemSelectedColor: "#0284c7",
      itemHoverColor: "#0284c7",
    },
    Progress: {
      colorBgContainer: "#E2E8F0",
      defaultColor: "#0284c7",
      remainingColor: "#E2E8F0",
    },
    Switch: {
      colorPrimary: "#0284c7",
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
      itemSelectedColor: "#0284c7",
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
      multipleItemBorderColor: "#bae6fd",
      optionSelectedBg: "#EFF6FF",
      optionActiveBg: "#F8FAFC",
    },
    DatePicker: {
      colorBgContainer: "#FFFFFF",
      colorBorder: "#CBD5E1",
      activeBorderColor: "#0284c7",
      hoverBorderColor: "#7dd3fc",
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
      navArrowColor: "#0284c7",
      waitIconColor: "#94A3B8",
      waitTitleColor: "#94A3B8",
      finishIconColor: "#0284c7",
      finishTitleColor: "#0F172A",
      processIconBg: "#0284c7",
      processIconColor: "#FFFFFF",
      processTitleColor: "#0284c7",
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
      trackBg: "#0284c7",
      trackHoverBg: "#38bdf8",
      dotBorderColor: "#CBD5E1",
      dotActiveBorderColor: "#0284c7",
      handleColor: "#0284c7",
      handleActiveColor: "#38bdf8",
    },
    Spin: {
      colorBgContainer: "transparent",
    },
    Empty: {
      colorBgContainer: "transparent",
    },
    Avatar: {
      colorBgContainer: "#EFF6FF",
      colorText: "#0284c7",
    },
    Dropdown: {
      colorBgContainer: "#FFFFFF",
      colorPrimary: "#0284c7",
    },
    Breadcrumb: {
      colorBgContainer: "transparent",
      itemColor: "#64748B",
      lastItemColor: "#0F172A",
      linkColor: "#0284c7",
      separatorColor: "#94A3B8",
    },
    Pagination: {
      colorBgContainer: "#FFFFFF",
      colorBorder: "#CBD5E1",
      colorPrimary: "#0284c7",
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
      linkColor: "#0284c7",
      linkHoverColor: "#38bdf8",
      linkActiveColor: "#0369a1",
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
