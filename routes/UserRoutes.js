const express = require("express")
const router = express.Router()


// Import the required controllers and middleware functions
const {registration, login, logout ,sendotp ,resetpassword}=require("../controller/Auth")

//middelweres api 
const {isValidUser}=require("../middlewares/auth")





// Route for user registration
router.post("/registration", registration)
// Route for user login
router.post("/login", login) 

// Route for user forgot and reset password
router.post("/sendotp",isValidUser , sendotp)
router.put("/reset-password",isValidUser ,resetpassword)





// Route for user logout
router.post("/logout",isValidUser ,logout)





module.exports = router