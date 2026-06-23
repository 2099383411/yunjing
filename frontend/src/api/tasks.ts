import client from "./client";

export const listTasks = () => client.get("/tasks/");
export const getTask = (id: string) => client.get(`/tasks/${id}`);
