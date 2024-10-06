const User = require("../models/User")
const jwt = require("jsonwebtoken")
require("dotenv").config()
const bcrypt = require("bcrypt")
const OTP = require("../models/OTP")
const otpGenerator = require("otp-generator")
const { check, validationResult, validationErrors } = require("express-validator");




// registration controller 
exports.registration = async (req, res) => {
    try {
        // Destructure fields from the request body
        const {
            name,
            email,
            password,
            phone,
            profile
        } = req.body
        // Check if All Details are there or not
        if (
            !name ||
            !email ||
            !password ||
            !phone
        ) {
            return res.status(403).send({
                success: false,
                message: "All Fields are required",
            })
        }

        //validation check
        const validationErrors = [];
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        //email validtion
        if (!emailRegex.test(email)) {
            validationErrors.push("Invalid email format.");
        }


        // Phone number validation: check if phone number contains only digits and has 10 digits (for example)
        const phoneRegex = /^[0-9]{10}$/;  // Modify this based on your country's phone number format
        if (!phoneRegex.test(phone)) {
            validationErrors.push("Invalid phone number. Must contain 10 digits.");
        }

        // Password validation: check if the password length is at least 6 characters
        if (password.length < 6) {
            validationErrors.push("Password must be at least 6 characters long.");
        }

        // If validation errors exist, return the errors
        if (validationErrors.length > 0) {
            return res.status(400).json({
                success: false,
                errors: validationErrors,
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email })
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: "User already exists. Please sign in to continue.",
            })
        }


        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10)


        // Create the Additional Profile For User
        const user = await User.create({
            name,
            email,
            password: hashedPassword,
            phone,
            profile

        })

        return res.status(200).json({
            success: true,
            user,
            message: "User registered successfully",
        })
    } catch (error) {
        console.error(error)
        return res.status(500).json({
            success: false,
            message: "User cannot be registered. Please try again.",
        })
    }
}




// Login controller for authenticating users
exports.login = async (req, res) => {
    try {
        // Get email and password from request body
        const { email, password } = req.body

        // Check if email or password is missing
        if (!email || !password) {
            // Return 400 Bad Request status code with error message
            return res.status(400).json({
                success: false,
                message: `Please Fill up All the Required Fields`,
            })
        }

        const validationErrors = [];

        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            validationErrors.push("Invalid email format.");
        }

        // Password validation: check if the password length is at least 6 characters
        if (password.length < 6) {
            validationErrors.push("Password must be at least 6 characters long.");
        }

        // If validation errors exist, return the errors
        if (validationErrors.length > 0) {
            return res.status(400).json({
                success: false,
                errors: validationErrors,
            });
        }

        // Find user with provided email
        const user = await User.findOne({ email })

        // If user not found with provided email
        if (!user) {
            // Return 401 Unauthorized status code with error message
            return res.status(401).json({
                success: false,
                message: `User is not Registered with Us Please SignUp to Continue`,
            })
        }

        // Generate JWT token and Compare Password
        if (await bcrypt.compare(password, user.password)) {
            const token = jwt.sign(
                { email: user.email, id: user._id },
                process.env.JWT_SECRET,
                {
                    expiresIn: "24h",
                }
            )

            // Save token to user document in database
            user.token = token
            user.password = undefined
            // Set cookie for token and return success response
            const options = {
                expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
                httpOnly: true,
            }
            res.cookie("token", token, options).status(200).json({
                success: true,
                token,
                user,
                message: `User Login Success`,
            })
        } else {
            return res.status(401).json({
                success: false,
                message: `Password is incorrect`,
            })
        }
    } catch (error) {
        console.error(error)
        // Return 500 Internal Server Error status code with error message
        return res.status(500).json({
            success: false,
            message: `Login Failure Please Try Again`,
        })
    }
}



//logout
exports.logout = async (req, res) => {
    try {
        res.clearCookie('token', { httpOnly: true, secure: true });
        res.status(200).send('Logged out successfully');

    } catch (error) {
        return res.status(500).json({
            message: error.message
        })

    }
}



// forgot-password 

exports.sendotp = async (req, res) => {

    try {
        const { email } = req.body;
        //validation
        if (!email) {
            return res.status(403).send({
                success: false,
                message: "All Fields are required",
            })
        }


        const validationErrors = [];

        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            validationErrors.push("Invalid email format.");
        }

       
      
        // If validation errors exist, return the errors
        if (validationErrors.length > 0) {
            return res.status(400).json({
                success: false,
                errors: validationErrors,
            });
        }

        // Check if the email exists
        const user = User.find({ email })



        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        var otp = otpGenerator.generate(6, {
            upperCaseAlphabets: false,
            lowerCaseAlphabets: false,
            specialChars: false,
        })
        const result = await OTP.findOne({ otp: otp })
        console.log("Result is Generate OTP Func")
        console.log("OTP", otp)
        console.log("Result", result)
        while (result) {
            otp = otpGenerator.generate(6, {
                upperCaseAlphabets: false,
            })
        }
        const otpPayload = { email, otp }
        const otpBody = await OTP.create(otpPayload)
        console.log("OTP Body", otpBody)
        res.status(200).json({
            success: true,
            message: `OTP Sent Successfully`,
            otp,
        })

    } catch (error) {
        console.log(error.message)
        return res.status(500).json({ success: false, error: error.message })

    }

}


//reset-password

exports.resetpassword = async (req, res) => {
    try {



        const { email, otp, newPassword } = req.body;

        //validation 
        if (
            !otp ||
            !email ||
            !newPassword
        ) {
            return res.status(403).send({
                success: false,
                message: "All Fields are required",
            })
        }



        //validation here
        const validationErrors = [];

        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            validationErrors.push("Invalid email format.");
        }

        // Password validation: check if the password length is at least 6 characters
        if (newPassword.length < 6) {
            validationErrors.push("Password must be at least 6 characters long.");
        }

        // If validation errors exist, return the errors
        if (validationErrors.length > 0) {
            return res.status(400).json({
                success: false,
                errors: validationErrors,
            });
        }



        // Find the user by email
        const user = User.find({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }


        // Check if OTP is valid
        const response = await OTP.find({ email }).sort({ createdAt: -1 }).limit(1)
        console.log(response)


        if (response.length === 0) {
            // OTP not found for the email
            return res.status(400).json({
                success: false,
                message: "The OTP is not valid",
            })
        } else if (otp !== response[0].otp) {
            // Invalid OTP
            return res.status(400).json({
                success: false,
                message: "The OTP is not valid",
            })
        }


        // Update password
        const encryptedPassword = await bcrypt.hash(newPassword, 10)
        const updatedUserDetails = await User.findByIdAndUpdate(
            req.user.id,
            { password: encryptedPassword },
            { new: true }
        )


        // Remove the OTP after successful reset
        const removeOtpFromDatabase = await OTP.deleteOne({ email: req.user.email })
        console.log("removeOtpFromDatabase", removeOtpFromDatabase)



        return res.status(200).json({

            success: true,
            message: "Password updated successfully"
        })



    }
    catch (error) {
        console.error("Error occurred while updating password:", error)
        return res.status(500).json({
            success: false,
            message: "Error occurred while updating password",
            error: error.message,
        })

    }
}