import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pkg from 'pg';
import nodemailer from "nodemailer";
import cors from 'cors';
const app=express();
app.use(cors());
const {Pool}=pkg;
const db=new Pool({
    user:process.env.DB_USER,
    host:process.env.DB_HOST,
    password:process.env.DB_PASSWORD,
    port:process.env.DB_PORT,
    database:process.env.DB_NAME,
    ssl:{
        rejectUnauthorized:false
    }
});
const backend="https://rajeev2004.github.io/ATG";
const key=process.env.JWT_KEY;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.post('/register',async(req,res)=>{
    try{
        const {name,email,pass}=req.body;
        if(name && email && pass){
            const result=await db.query("select * from users where username=$1 OR email=$2",[name,email]);
            if(result.rows.length>0){
                return res.status(400).json({message:'user already exist'});
            }
        }
        const hashedPassword=await bcrypt.hash(pass,10);
        const response=await db.query("insert into users (email,password,username) values($1,$2,$3) RETURNING *",[email,hashedPassword,name]);
        const token=jwt.sign({userId:response.rows[0].id},key,{expiresIn:'1h'});
        res.status(201).json({token,message:'user registered'});
    }catch(err){
        console.error(err.message);
        res.status(500).json({message:'server error'});
    }
})
app.post('/login',async(req,res)=>{
    try{
        const{email,pass}=req.body;
        const result=await db.query("select * from users where email=$1",[email]);
        if(result.rows.length===0){
            return res.status(400).json({message:'no user found'});
        }
        const isPasswordCorrect=await bcrypt.compare(pass,result.rows[0].password);
        if(!isPasswordCorrect){
            return res.status(400).json({message:'invalid email or password'});
        }
        const token=jwt.sign({userId:result.rows[0].id},key,{expiresIn:'1h'});
        res.status(200).json({token,message:'login successful'});
    }catch(err){
        console.error(err.message);
        res.status(500).json({message:'server error'});
    }
})
app.post('/forgot-pass',async(req,res)=>{
    try{
        const {email}=req.body;
        const result=await db.query("select * from users where email=$1",[email]);
        if(result.rows.length==0){
            return res.status(400).json({message:'no user found'});
        }
        const resetToken=jwt.sign({userId:result.rows[0].id},key,{expiresIn:'15m'});
        const transport=nodemailer.createTransport({
            service:"gmail",
            auth:{
                user:process.env.mail,
                pass:process.env.pass,
            },
        });
        const resetLink=`${backend}/reset-password?token=${resetToken}`;
        const mail={
            from:process.env.mail,
            to:email,
            subject:'reset password',
            text:`you requested to change ypur password. Use this token ${resetToken}`,
            html:`<p>Use the following link to reset your password</p>
                <p><a href="${resetLink}">Reset Password</a></p>`
        };
        transport.sendMail(mail);
        res.status(200).json({message:'Password reset token sent to your email'})
    }catch(err){
        console.error(err.message);
        res.status(500).json({message:'server error'});
    }
})
app.post('/reset-Password',async(req,res)=>{
    try{
        const {newpass,token}=req.body;
        const result=jwt.verify(token,key);
        const response=await db.query("select * from users where id=$1",[result.userId]);
        if(response.rows.length===0){
            return res.status(400).json({message:'no user found'});
        }
        const hashedPassword=await bcrypt.hash(newpass,10);
        await db.query("update users set password=$1 where id=$2",[hashedPassword,result.userId]);
        res.status(200).json({message:'Password successfully updated'});
    }catch(err){
        console.error(err.message);
        res.status(500).json({message:'server error'});
    }
})
    
const port=3000;
app.listen(port,()=>{
  console.log(`Server running on port ${port}`);
});

