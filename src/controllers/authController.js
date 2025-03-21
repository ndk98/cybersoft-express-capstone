import bcrypt from "bcrypt";
import crypto from "crypto";
import { PrismaClient } from "@prisma/client";
import transporter from "../configs/transporter.js";
import {
    createAccessToken,
    createRefreshToken,
    verifyAccessToken,
} from "../configs/jwt.js";

const prisma = new PrismaClient();

const register = async (req, res) => {
    try {
        let { full_name, email, pass_word } = req.body;

        const userExist = await prisma.users.findFirst({
            where: {
                email,
            },
        });

        if (userExist) {
            return res.status(400).json({ message: "Email already exists" });
        }

        const hashedPassword = bcrypt.hashSync(pass_word, 10);

        const data = await prisma.users.create({
            data: {
                full_name,
                email,
                pass_word: hashedPassword,
            },
        });

        // Send email to user
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Welcome to our website",
            html: `<h1>Hello ${full_name}, welcome to our website</h1>`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error);
            } else {
                console.log(`Email sent: ${info.response}`);
            }
        });

        data.dataValues.pass_word = undefined;

        return res.status(200).json(data);
    } catch (e) {
        return res.send(`Error: ${e}`);
    }
};

const login = async (req, res) => {
    try {
        let { email, pass_word } = req.body;

        const user = await prisma.users.findFirst({
            where: {
                email,
            },
        });

        if (!user) {
            return res.status(400).json({ message: "Email does not exist" });
        }

        const validPass = bcrypt.compareSync(pass_word, user.pass_word);

        if (!validPass) {
            return res.status(400).json({ message: "Invalid password" });
        }

        // Create access token for user
        const payload = {
            user_id: user.user_id,
            full_name: user.full_name,
            email: user.email,
        };

        const accessToken = createAccessToken(payload);

        const refreshToken = createRefreshToken(payload);

        await prisma.users.update({
            where: {
                user_id: user.user_id,
            },
            data: {
                refresh_token: refreshToken,
            },
        });

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: false,
            sameSite: "Lax",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        // Remove password from user data
        user.dataValues.pass_word = undefined;

        return res
            .status(200)
            .json({ message: "Login successfully", accessToken });
    } catch (e) {
        return res.status(401).json({ message: e.message });
    }
};

const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await prisma.users.findFirst({
            where: {
                email,
            },
        });

        if (!user) {
            return res.status(400).json({ message: "Email does not exist" });
        }

        const code = crypto.randomBytes(6).toString("hex");

        const existForgotCode = await prisma.forgot_password_code.findFirst({
            where: {
                user_id: user.user_id,
            },
        });

        const expired = new Date(Date.now() + 2 * 60 * 60 * 1000);
        if (existForgotCode) {
            await prisma.forgot_password_code.update({
                where: {
                    user_id: user.user_id,
                },
                data: {
                    forgot_code: code,
                    expired: expired,
                },
            });
        } else {
            await prisma.forgot_password_code.create({
                data: {
                    user_id: user.user_id,
                    forgot_code: code,
                    expired: expired,
                },
            });
        }

        // Send email to user
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Reset password",
            html: `<h1>Hello ${user.full_name}, you can reset your password with code: ${code}</h1>`,
        };

        return transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(500).json({ message: "Email sent error!" });
            }
            return res.status(200).json({ message: "Email sent successfully" });
        });
    } catch (e) {
        return res.send(`Error: ${e}`);
    }
};

const resetPassword = async (req, res) => {
    try {
        const { email, code, new_password } = req.body;

        const user = await prisma.users.findFirst({
            where: {
                email,
            },
        });

        if (!user) {
            return res.status(400).json({ message: "Email does not exist" });
        }

        const forgotCode = await prisma.forgot_password_code.findFirst({
            where: {
                user_id: user.user_id,
                forgot_code: code,
            },
        });

        if (!forgotCode) {
            return res.status(400).json({ message: "Code is invalid" });
        }

        if (new Date(forgotCode.expired) < new Date()) {
            return res.status(400).json({ message: "Code is expired" });
        }

        const hashedPassword = bcrypt.hashSync(new_password, 10);

        await prisma.users.update({
            where: {
                user_id: user.user_id,
            },
            data: {
                pass_word: hashedPassword,
            },
        });

        await prisma.forgot_password_code.delete({
            where: {
                user_id: user.user_id,
            },
        });

        return res.status(200).json({ message: "Reset password successfully" });
    } catch (e) {
        return res.send(`Error: ${e}`);
    }
};

const extendToken = async (req, res) => {
    try {
        const { refreshToken } = req.cookies;

        if (!refreshToken) {
            return res.status(400).json({ message: "Refresh token not found" });
        }

        const checkToken = verifyAccessToken(refreshToken);

        if (!checkToken) {
            return res.status(403).json({ message: "Invalid refresh token" });
        }

        const user = await prisma.users.findFirst({
            where: {
                user_id: checkToken.payload.user_id,
            },
        });

        if (!user) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const payload = {
            user_id: user.user_id,
            full_name: user.full_name,
            email: user.email,
        };

        const accessToken = createAccessToken({ payload });

        return res
            .status(200)
            .json({ message: "Extend successfully", accessToken });
    } catch (e) {
        return res.status(500).json({ message: "Extend failed" });
    }
};

export { register, login, forgotPassword, resetPassword, extendToken };
