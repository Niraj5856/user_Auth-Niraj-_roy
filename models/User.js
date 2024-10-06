const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
	{

		name: {
			type: String,
			required: true,
			trim: true,
		},

		email: {
			type: String,
			required: true,
			trim: true,
			unique:true,
			lowercase:true
		},
		phone:{
			type: Number,
			required: true,
			trim: true,
			unique:true,
			
		}
		,
		dob:{
			type:Date
		},


		password: {
			type: String,
			required: true,
			minlength: 6,
			
		},
		profile:{
			type:String ,
			default:"",
		}

	},
	{ timestamps: true }
);

// Export the Mongoose model for the user schema, using the name "user"
module.exports = mongoose.model("user", userSchema);

