const express = require("express");
const userdb = require("../models/userSchema");
const router = new express.Router();
const bcrypt = require('bcryptjs');
const authenticate = require("../middleware/authenticate");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken")


const  keysecret = "durgeshchaudharydurgeshchaudhary";

// email config
const transporter = nodemailer.createTransport({
    service:"gmail",
    auth:{
        user:"durgeshchaudhary020401@gmail.com",
        pass:"lqfxwpogsaocehjc"
    }
})


/// for user rgistration 

router.post('/register', async (req, res) => {
    // console.log(req.body);

    const { fname, email, password, cpassword } = req.body;

    if (!fname || !email || !password || !cpassword) {
        res.status(404).json({ error: "fill all the deatils" })
    }
    try {
        const preuser = await userdb.findOne({ email: email });
        if (preuser) {
            res.status(404).json({ error: "This Email is Already Exist" });
        } else if (password !== cpassword) {
            res.status(404).json({ error: "This Email is Already Exist" });
        } else {
            const finalUser = new userdb({
                fname, email, password, cpassword
            });

            // here password hashing
            const storeData = await finalUser.save();
            //  console.log(storeData);
            res.status(201).json({ status: 201, storeData })
        }

    } catch (error) {
        res.status(404).json({ error });
        console.log("catch block error");
    }
})

// user Login

router.post("/login", async (req, res) => {
    // console.log(req.body);

    const { email, password } = req.body;

    if (!email || !password) {
        res.status(422).json({ error: "fill all the details" })
    }

    try {
       const userValid = await userdb.findOne({email:email});

        if(userValid){

            const isMatch = await bcrypt.compare(password,userValid.password);

            if(!isMatch){
                res.status(422).json({ error: "invalid details"})
            }else{

                // token generate
                const token = await userValid.generateAuthtoken();

                // cookiegenerate
                res.cookie("usercookie",token,{
                    expires:new Date(Date.now()+9000000),
                    httpOnly:true
                });

                const result = {
                    userValid,
                    token
                }
                res.status(201).json({status:201,result})
            }
        }

    } catch (error) {
        res.status(401).json(error);
        console.log("catch block");
    }
});



// user valid
router.get("/validuser", authenticate, async(req,res)=>{
    try {
        const ValidUserOne = await userdb.findOne({_id:req.userId});
        res.status(201).json({status:201,ValidUserOne});
    } catch (error) {
        res.status(401).json({status:401,error});
    }
});

router.get("/logout", authenticate, async(req, res)=>{
    try {
        req.rootUser.tokens = req.rootUser.tokens.filter((curelem)=>{
             return curelem.token !== req.token
        }) 

        res.clearCookie("usercookie", {path:"/"});

        req.rootUser.save();

        res.status(201).json({status:201})

    } catch (error) {
        res.status(401).json({status:401, error})
    }
});



// send email link for reset password

router.post("/sendpasswordlink", async(req, res)=>{
    console.log(req.body)

    const {email} = req.body;
    
    if(!email){
        res.status(401).json({status:401, message:"Enter Your Email"})
    }
 
    try {
        const userfind = await userdb.findOne({email:email});

        // console.log("userfind", userfind)
        // token generate for reset password
        const token = jwt.sign({_id:userfind._id},keysecret,
            {
                expiresIn:"1d"
            })
            // console.log("token",token)
            const setusertoken = await userdb.findByIdAndUpdate({_id:userfind._id},{verifytoken:token},{new:true})
            // console.log(" setusertoken", setusertoken)

            if(setusertoken){
                const mailOptions = {
                    from:"durgeshchaudhary020401@gmail.com",
                    to:email,
                    subject:"sending email of password Reset",
                    text:`this link valid for 2 minutes http://localhost:3000/forgotpassword/${userfind.id}/${setusertoken.verifytoken}`
                }

                transporter.sendMail(mailOptions,(error,info)=>{
                    if(error){
                        console.log('error',error);
                        res.status(401).json({status:401, message:"email not send"})
                    }else{
                        console.log("Email sent ",info.response);
                        res.status(201).json({status:201, message:"email send successfully"})
                    }
                })
            }
    } catch (error) {
        res.status(201).json({status:201, message:"Invalid user"})
    }
})


// verify user for forgot password time

router.get("/forgotpassword/:id/:token", async(req,res)=>{
    const {id, token}=req.params;
    // console.log(id, token)

    try {
        const validuser = await userdb.findOne({_id:id,  verifytoken:token});
        // console.log(validuser)
          
        // verify user token 
        const verifyToken = jwt.verify(token, keysecret);
         
        // console.log(verifyToken)

        if(validuser && verifyToken._id){
            res.status(201).json({status:201, validuser})
        }else{
            res.status(401).json({status:401, message:"user not exist"})
        }

    } catch (error) {
        res.status(401).json({status:401, error})
    }
    
});

// change password

router.post("/:id/:token", async(req, res)=>{
    const {id, token} = req.params;

    const {password}= req.body;

    try {
         
        const validuser = await userdb.findOne({_id:id,  verifytoken:token});
        // console.log(validuser)
          
        // verify user token 
        const verifyToken = jwt.verify(token, keysecret);

        if(validuser && verifyToken._id){
            const newpassword = await bcrypt.hash(password, 12)

            // update user password
            const setnewuserpass = await userdb.findByIdAndUpdate({_id:id},{password: newpassword});

            setnewuserpass.save()  //save user
            res.status(201).json({status:201, setnewuserpass})

        }else{
            res.status(401).json({status:401, message:"user not exist"})
        }
    } catch (error) {
        res.status(401).json({status:401, error})
    }
})

module.exports = router;