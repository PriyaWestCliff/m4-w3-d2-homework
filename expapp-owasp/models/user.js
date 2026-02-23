const mongoose = require("mongoose");
const passportLocalMongoose = require("passport-local-mongoose").default; 

const UserSchema = new mongoose.Schema({
  username: String,
  email: String,
  phone: Number
});

UserSchema.plugin(passportLocalMongoose); // auto salt + hash

module.exports = mongoose.model("User", UserSchema);