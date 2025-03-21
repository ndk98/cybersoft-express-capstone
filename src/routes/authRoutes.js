import express from "express";
import {
    forgotPassword,
    login,
    register,
    resetPassword,
    extendToken,
} from "../controllers/authController.js";

const authRoutes = express.Router();

authRoutes.post("/register", register);

authRoutes.post("/login", login);

authRoutes.post("/forgot-password", forgotPassword);

authRoutes.post("/reset-password", resetPassword);

authRoutes.post("/extend-token", extendToken);

export default authRoutes;
