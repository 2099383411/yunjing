import axios from "axios";

const client = axios.create({
  baseURL: "/api",
  timeout: 60000,
  headers: { "Content-Type": "application/json" },
});

client.interceptors.request.use((config) => {
  const token = localStorage.getItem("yunjing_token");
  if (token) {
    config.headers.Authorization = "Bearer " + token;
  }
  return config;
});

client.interceptors.response.use(
  (res) => res,
  (err) => {
    console.error("API Error:", err?.response?.status);
    if (err?.response?.status === 401 && !window.location.pathname.startsWith("/login")) {
      localStorage.removeItem("yunjing_token");
      window.location.href = "/login";
    }
    return Promise.reject(err);
  }
);

export default client;
