import { HashRouter } from "react-router-dom";
import { ConfigProvider, App as AntApp } from "antd";
import zhCN from "antd/locale/zh_CN";
import { brandTheme } from "./theme";
import Router from "./router";

export default function App() {
  return (
    <ConfigProvider theme={brandTheme} locale={zhCN}>
      <AntApp>
        <HashRouter>
          <Router />
        </HashRouter>
      </AntApp>
    </ConfigProvider>
  );
}
