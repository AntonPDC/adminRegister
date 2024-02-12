import { Admin, IAdmin } from "../models/admin";
import { User, IUser } from "../models/User";
import { Response, Request } from "express";
import { hash } from "bcryptjs";

// Searches our DB for members in either the users or admins sections of the collection
const findUserOrAdminByEmail = async (
  email: string
): Promise<IUser | IAdmin | null> => {
  const user = await User.findOne({ email: email });
  if (user) {
    return user;
  }
  const admin = await Admin.findOne({ email: email });
  return admin;
};

//Function that will create verifcation code for OTP
export const generateOTP = (): string => {
  const generatedCode = crypto.randomBytes(3).toString("hex");
  const code = generatedCode.toUpperCase();
  return code;
};

// Our function to generate our one-time password for email verification
const generateOtp1 = async (email: string): Promise<string | Error> => {
  try {
    //Where our find member function is called asynchronously
    let user: IUser | IAdmin | null = await findUserOrAdminByEmail(email);
    //if user is null, throw an error
    if (!user) {
      throw new Error("Invalid Email");
    }
    //if user has had too many attempts at OTP verifcations, throw an error
    if (user.isBlocked) {
      const currentTime = new Date();
      if (currentTime < user.blockUntil) {
        throw new Error("Account blocked. Try after some time.");
      } else {
        user.isBlocked = false;
        user.OTPAttempts = 0;
      }
    }
    const lastOTPTime = user.OTPCreatedTime;
    const currentTime = new Date();
    if (lastOTPTime && currentTime.getTime() - lastOTPTime.getTime() < 60000) {
      throw new Error("Minimum 1-minute gap required between OTP requests");
    }

    //Where we actually create the code and save it
    const OTP: string = user.generateOTP();
    user.OTP = OTP;
    user.OTPCreatedTime = currentTime;

    await user.save();

    user.sendOTP();

    return OTP;
  } catch (err: any) {
    console.log(err);
    return Error("Server Error");
  }
};

// Regex for formatting email / password fields
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;

export const registerAdmin = async (
  req: Request,
  res: Response
): Promise<Response> => {
  const { name, email, username, password, confirmPassword } = req.body as {
    name: string;
    email: string;
    username: string;
    password: string;
    confirmPassword: string;
  };

  //Tests if email is valid format AND has the correct domain for admin purposes
  if (!emailRegex.test(email) || email.split("@")[1] !== "airbnb.com") {
    return res.status(400).json({ message: "Not a valid email address" });
  }
  //Tests if password is valid format
  if (!passwordRegex.test(password)) {
    return res.status(400).json({ message: "Not a valid password" });
  }
  //Check if passwords match
  if (password !== confirmPassword) {
    return res.status(400).json({ message: "Passwords do not match" });
  }

  try {
    //Try to find a user with the same email or username
    const existingUser: IAdmin | null = await Admin.findOne({
      $or: [{ email: email }, { username: username }],
    });

    if (existingUser) {
      return res
        .status(400)
        .json({ message: "User with this email or username already exists" });
    }
    //Make sure we are hashing password for security
    const hashedPassword = await hash(password, 10);
    const roles = ["supportAdmin"];
    //Create new Admin user
    const newAdmin = new Admin({
      name,
      email,
      username,
      password: hashedPassword,
      roles: roles,
    });

    await newAdmin.save();

    // Generate OTP, send it to the new saved admin object, and verify it
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
    //Generate a JWT token for the new admin, and return it
    const authToken = newAdmin.generateAuthToken();
    return res.json({ token: authToken });
  } catch (error: any) {
    console.error("Error registering user:", error);
    return res
      .status(500)
      .json({ message: "Internal Server Error - Registration failed" });
  }
};
