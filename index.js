const express = require("express");
const app = express();

const userRoutes = require("./user_Auth-Niraj-_roy/routes/UserRoutes");
const database=require("./user_Auth-Niraj-_roy/config/dataBase")
const cookieParser = require("cookie-parser");
const dotenv = require("dotenv");

dotenv.config();
const PORT = process.env.PORT || 4000;

//database connect
database.connect();   
//middlewares
app.use(express.json());
app.use(cookieParser());





//routes
app.use("/api/v1/auth", userRoutes);


//def route

app.get("/", (req, res) => {
	return res.json({
		success:true,
		message:'Your server is up and running....'
	});
});

app.listen(PORT, () => {
	console.log(`App is running at ${PORT}`)
})

