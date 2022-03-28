const express = require("express");
var router = express.Router();
let {userModel} = require("../../models/user");
const validateUser = require("../../middlewares/validateuser");
const validateuserLogin = require("../../middlewares/validateuserlogin");
var bcrypt = require("bcryptjs");
const _ = require("lodash");
const jwt = require("jsonwebtoken");
const config = require("config");
const auth = require("../../middlewares/auth");
const admin = require("../../middlewares/admin");
//for sign-up
router.post("/register",validateUser,async (req,res)=>{
    let user = await userModel.findOne({email : req.body.email});
    if(user)
    {
        return res.status(400).send("Email already exists");
    }
    user = new userModel();
    user.name = req.body.name;
    user.email = req.body.email;
    user.password = req.body.password;
    await user.generateHashedPassword();
    await user.save();
    return res.send(_.pick(user,["name","email"]));
});

//for login
router.post("/login",validateuserLogin,async (req,res)=>{
    let user = await userModel.findOne({email : req.body.email});
    if(!user)
    {
        return res.status(400).send("User Not Registered");
    }
    let isvalid = await bcrypt.compare(req.body.password,user.password);
    if(!isvalid)
    {
        return res.status(401).send("Invalid Password");
    }
    let token = jwt.sign({_id:user._id,name:user.name},config.get("jwtPrivateKey"));
    res.send(token);
    
});

router.get("/",auth,async (req,res)=>{
    let user = await userModel.find();
    return res.send(user);
});

router.get("/:id",auth,async (req,res)=>{
    let user = await userModel.findById(req.params.id);
    return res.send(user);
});

router.post("/",auth,admin,validateUser,async (req,res)=>{
    let user = await userModel.findOne({email : req.body.email});
    if(user)
    {
        return res.status(400).send("Email already exists");
    }
    user = new userModel();
    user.name = req.body.name;
    user.email = req.body.email;
    user.password = req.body.password;
    await user.generateHashedPassword();
    await user.save();
    return res.send(_.pick(user,["name","email"]));
});

router.put("/:id",auth,admin,validateUser,async (req,res)=>{
    let user = await userModel.findById(req.params.id);
    user.name = req.body.name;
    user.email = req.body.email;
    user.password = req.body.password;
    await user.generateHashedPassword();
    await user.save();
    return res.send(_.pick(user,["name","email"]));
});

router.delete("/:id",auth,admin,async(req,res)=>{
    let user = await userModel.findByIdAndDelete(req.params.id);
    return res.send(user);
});





module.exports = router;