import express from "express";
import authRoutes from "./authRoutes.js";

const rootRoutes = express.Router();

rootRoutes.use("/auth", authRoutes);

export default rootRoutes;
