import client from "./client";

export const getSettings = () => client.get("/settings/");
