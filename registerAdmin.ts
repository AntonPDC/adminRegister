import { Admin, IAdmin } from "../models/admin";
import { Response, Request, NextFunction } from "express";
import { hash } from "bcryptjs";
import { emailRegex, passwordRegex } from "../utils/regex";
import {
  findUserByEmail,
  generateOtp1,
  sendAdminInviteEmail,
} from "../utils/verifyEmail";

export const adminInvite = async (req: Request, res: Response) => {
  const { email } = req.body;
  const emailExists = await findUserByEmail(email); //searches for USERS not admin
  if (!emailExists /*|| email.split("@")[1] !== "raycabio.com"*/) {
    return res
      .status(404)
      .json({ status: false, message: "Email not valid for invitation." });
  }
  try {
    const sendInvite = sendAdminInviteEmail(email);
    sendInvite;
    return res.status(200).json({ message: "Admin Invite sent" });
  } catch (error) {
    console.log("error: ", error);
    return res.status(500).json({ messsage: "Internal Server Error" });
  }
};

export const registerSupportAdmin = async (
  req: Request,
  res: Response
): Promise<Response> => {
  const { name, email, username, password, confirmPassword } = req.body as {
    name: string;
    email: string;
    username: string;
    password: string;
    confirmPassword: string;
  }; //commented out for testing, but it parses the domain
  if (!emailRegex.test(email) /*|| email.split("@")[1] !== "raycabio.com"*/) {
    return res.status(400).json({ message: "Not a valid email address" });
  }

  if (!passwordRegex.test(password)) {
    return res.status(400).json({ message: "Not a valid password" });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ message: "Passwords do not match" });
  }

  try {
    const existingUser: IAdmin | null = await Admin.findOne({
      $or: [{ email: email }, { username: username }],
    });

    if (existingUser) {
      return res
        .status(400)
        .json({ message: "User with this email or username already exists" });
    }

    const hashedPassword = await hash(password, 10);
    const roles = ["supportAdmin"];

    const newAdmin = new Admin({
      name,
      email,
      username,
      password: hashedPassword,
      roles: roles,
    });

    await newAdmin.save();
    const otpResult = await generateOtp1(newAdmin.email);
    if (otpResult instanceof Error) {
      console.error("Error generating OTP:", otpResult.message);

      if (otpResult.message === "Invalid Email and/or password") {
        if (!emailRegex.test(email)) {
          return res.status(400).json({ message: "Invalid Email provided" });
        }
      } else {
        return res
          .status(500)
          .json({ message: "Internal Server Error - OTP generation failed" });
      }
    }

    const authToken = newAdmin.generateAuthToken();
    return res.json({ token: authToken });
  } catch (error: any) {
    console.error("Error registering user:", error);
    return res
      .status(500)
      .json({ message: "Internal Server Error - Registration failed" });
  }
};
