require("dotenv").config();
const express = require("express");
const session = require("express-session");
const { Pool } = require("pg");
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const otpVerifyLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  message: { success:false, message:"Too many OTP attempts" }
});
const strictLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // only 10 requests per minute
  message: { success:false, message:"Too many requests" }
});
const validator = require("validator");
const cors = require("cors");
const helmet = require("helmet");

const csurf = require("csurf");
 
// structure:
// {
//   email: {
//     otp: "123456",
//     expires: timestamp,
//     attempts: 0
//   }
// }
const app = express();
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "lax"
  }
}));
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100, // overall requests
  message: "Too many requests from this IP"
});

app.disable("x-powered-by");
app.use(express.static("public", {
  dotfiles: "ignore",
  index: false
}));
app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/signup.html");
});
app.get("/home", (req, res) => {
    res.sendFile(__dirname + "/public/home.html");
});
app.get("/profile", (req, res) => {
    res.sendFile(__dirname + "/public/profile.html");
});

app.get("/wallet", (req, res) => {
    res.sendFile(__dirname + "/public/wallet.html");
});

app.get("/admin", isMainAdmin, (req, res) => {
    res.sendFile(__dirname + "/private/admin.html");
});
app.get("/history", (req, res) => {
    res.sendFile(__dirname + "/public/history.html");
});
function isMinorAdmin(req,res,next){
  if(req.session.isMinorAdmin){
    return next();
  }
  return res.status(403).json({success:false});
}

app.get("/minor-admin", isMinorAdmin, (req, res) => {
    res.sendFile(__dirname + "/private/minor-admin.html");
});
app.get("/session", (req, res) => {
    res.sendFile(__dirname + "/public/session.html");
});
app.use(
  helmet({
    contentSecurityPolicy: false
  })
);
app.set("trust proxy", 1);
if (process.env.NODE_ENV === "production") {
  app.use((req, res, next) => {
    if (req.headers["x-forwarded-proto"] !== "https") {
      return res.redirect("https://" + req.headers.host + req.url);
    }
    next();
  });
}
app.use(cors({
  origin: process.env.FRONTEND_URL, // for now (your local site)
  credentials: true
}));
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 🔒 stricter
  message: { success:false, message:"Too many login attempts. Try later." },
  standardHeaders: true,
  legacyHeaders: false,
});
const withdrawLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { success:false, message:"Too many withdraw attempts" }
});
const otpSendLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 min
  max: 3,
  message: { success:false, message:"Wait before requesting OTP again" }
});
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
pass: process.env.EMAIL_PASS
  }
});

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true }));

const csrfProtection = csurf({
  cookie: false // because you're using sessions
});



const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});
// ✅ SESSION QUESTIONS CONFIG
const sessionQuestions = [

  // 🏆 TOURNAMENT (10x, one bet only)
  {
    id:1,
    type:"tournament",
    question:"Which Team will win IPL 2026?",
    odds:100,
    oneBet:true,
    is_open:true,
    correct:null
  },
  {
    id:2,
    type:"tournament",
    question:"Which team will score the highest total this season?",
    odds:100,
    oneBet:true,
    is_open:true,
    correct:null
  },
  {
    id:3,
    type:"tournament",
    question:"Which Team will have the orange cap holder?",
    odds:100,
    oneBet:true,
    is_open:true,
    correct:null
  },
  {
    id:4,
    type:"tournament",
    question:"Which team will have the purple cap holder?",
    odds:100,
    oneBet:true,
    is_open:true,
    correct:null
  },

  // ⚡ MATCH (1.5x)
  {
    id:5,
    type:"match",
    question:"Total Runs in 1st innings?",
    odds:1.7,
    options:["150+","200+","250+","300+"],
    is_open:true,
    correct:null
  },
  {
    id:6,
    type:"match",
    question:"Total Runs in 2nd innings?",
    odds:1.7,
    options:["150+","200+","250+","300+"],
    is_open:true,
    correct:null
  },
  {
    id:7,
    type:"match",
    question:"Total Runs in PowerPlay?",
    odds:1.7,
    options:["40+","50+","70+","90+"],
    is_open:true,
    correct:null
  },
  {
    id:8,
    type:"match",
    question:"Runs in last over?",
    odds:1.7,
    options:["5+","8+","18+","24+"],
    is_open:true,
    correct:null
  }

];
function isMainAdmin(req,res,next){

  if(req.session.isMainAdmin){
    return next();
  }

  return res.status(403).json({
  success:false,
  message:"Access denied"
});
}
function isValidNumber(val, min=0, max=100000){
  const num = Number(val);
  return !isNaN(num) && num >= min && num <= max;
}

function isValidId(val){
  return Number.isInteger(Number(val)) && Number(val) > 0;
}
function isLoggedIn(req, res, next){
  if(req.session && req.session.userId){
    return next();
  }

  console.log("NOT LOGGED IN:", req.session); // debug

  return res.redirect("/login.html");
}
function cleanInput(input){
  if(typeof input !== "string") return input;

  return validator.escape(input.trim());
}
/* LOGIN */
app.post("/login", csrfProtection, loginLimiter, async (req, res) => {
  const email = cleanInput(req.body.email).toLowerCase();
const password = req.body.password;
// ❌ block invalid email
if(!validator.isEmail(email)){
  return res.json({ success: false, message: "Invalid email or password" });
}

// ❌ block empty password
if(!password || password.length < 8){
  return res.json({ success: false, message: "Invalid email or password" });
}
  const result = await pool.query(
  "SELECT * FROM users WHERE email=$1",
  [email]
);

if(result.rows.length > 0){

  let user = result.rows[0];

  let match = false;

// If password is already hashed
if(user.password.startsWith("$2b$")){
  match = await bcrypt.compare(password, user.password);
} else {
  // Plaintext password → verify manually
  if(password === user.password){
    match = true;

    // 🔐 Upgrade to hashed password
    const newHash = await bcrypt.hash(password, 10);

    await pool.query(
      "UPDATE users SET password=$1 WHERE id=$2",
      [newHash, user.id]
    );
  }
}

  if(match){

  req.session.regenerate((err) => {
  if(err){
    return res.json({ success:false });
  }

  req.session.userId = user.id;

  (async () => {
    try {

      if(user.first_login){
        await pool.query(
          "UPDATE users SET balance = balance + 50, bonus = bonus + 50, first_login = false WHERE id=$1",
          [user.id]
        );

        req.session.showBonus = true;
      }

      // ✅ THIS IS THE FIX
      req.session.save((err) => {
        if(err){
          return res.json({ success:false });
        }

        return res.json({ success:true });
      });

    } catch(e){
      return res.json({ success:false });
    }
  })();
});

  return; // 🚨 IMPORTANT
}
}

res.json({ success: false, message: "Invalid email or password" });
});
app.get("/csrf-token", csrfProtection, (req,res)=>{
  res.json({ csrfToken: req.csrfToken() });
});
/* USER */
app.get("/user", isLoggedIn, async (req,res)=>{
  const result = await pool.query(
    "SELECT name,email FROM users WHERE id=$1",
    [req.session.userId]
  );
  res.json(result.rows[0]);
});

/* MATCHES */
app.get("/matches", async (req, res) => {
  const result = await pool.query(`
  SELECT 
  m.id,
  m.status,
  m.team1_id,
m.team2_id,
  m.favoured_team,
  m.match_date,
  m.rapid_open,
m.rapid_team,
m.toss_open,
m.toss_winner,
m.match_open,
m.team1_odds,
m.team2_odds,
m.scorer_open,
m.wicket_open,
  t1.name AS team1_name,
  t1.logo AS team1_logo,
  t2.name AS team2_name,
  t2.logo AS team2_logo
  FROM matches m
  JOIN teams t1 ON m.team1_id = t1.id
  JOIN teams t2 ON m.team2_id = t2.id
  ORDER BY m.id
  `);

  res.json(result.rows);
});

/* TEAMS */
app.get("/teams", async (req,res)=>{
  const result = await pool.query("SELECT * FROM teams ORDER BY id");
  res.json(result.rows);
});

/* UPDATE MATCHES */
app.post("/updateMatches", csrfProtection, isMainAdmin, async (req,res)=>{

  const {
    featuredTeam1,featuredTeam2,favoured,fDate,
    up1Team1,up1Team2,u1Date,
    up2Team1,up2Team2,u2Date,
    team1Odds, team2Odds   // ✅ ADD HERE
  } = req.body;
 
   if(!isValidId(featuredTeam1) || !isValidId(featuredTeam2)){
    return res.send("Invalid teams");
  }
  if(featuredTeam1 === featuredTeam2 ||
     up1Team1 === up1Team2 ||
     up2Team1 === up2Team2){
    return res.send("Error: Teams cannot be the same");
  }

  const featuredDate = fDate === "" ? null : fDate;
  const upDate1 = u1Date === "" ? null : u1Date;
  const upDate2 = u2Date === "" ? null : u2Date;
 const odds1 = team1Odds === "" ? null : Number(team1Odds);
const odds2 = team2Odds === "" ? null : Number(team2Odds);
  try{

    // 🧹 delete old matches
    await pool.query("UPDATE matches SET status='completed' WHERE status IN ('featured','upcoming')");
    // ✅ insert new featured
    await pool.query(`
    INSERT INTO matches 
(team1_id, team2_id, favoured_team, match_date, status, team1_odds, team2_odds)
VALUES ($1,$2,$3,$4,'featured',$5,$6)
    `,[featuredTeam1, featuredTeam2, favoured, featuredDate, odds1, odds2]);

    // ✅ insert upcoming 1
    await pool.query(`
    INSERT INTO matches (team1_id, team2_id, match_date, status)
    VALUES ($1,$2,$3,'upcoming')
    `,[up1Team1,up1Team2,upDate1]);

    // ✅ insert upcoming 2
    await pool.query(`
    INSERT INTO matches (team1_id, team2_id, match_date, status)
    VALUES ($1,$2,$3,'upcoming')
    `,[up2Team1,up2Team2,upDate2]);

    res.send("Matches Updated Successfully ✅");

  }catch(err){
    if(process.env.NODE_ENV !== "production"){
  console.error(err);
}
    res.send("Error updating matches");
  }

});
app.post("/setPlayerBets", csrfProtection, isMainAdmin, async (req,res)=>{
  const { match_id, players } = req.body;

  try{
    // delete old
    await pool.query(
      "DELETE FROM player_bets WHERE match_id=$1",
      [match_id]
    );

    // insert new
    for(let p of players){
      await pool.query(`
        INSERT INTO player_bets (match_id, player_name, team_id, bet_type, odds)
        VALUES ($1,$2,$3,$4,$5)
      `,[match_id, p.name, p.team_id, p.type, p.odds]);
    }

    res.send("Player bets updated ✅");

  }catch(err){
    if(process.env.NODE_ENV !== "production"){
  console.error(err);
}
    res.send("Error saving players");
  }
});
/* PAYMENT */
app.post("/requestPayment", csrfProtection, loginLimiter, async (req,res)=>{

  const name = cleanInput(req.body.name);
const amount = req.body.amount;
const transaction_id = cleanInput(req.body.transaction_id);
if(!isValidNumber(amount, 20, 1000)){
  return res.json({success:false});
}
  if(!req.session.userId){
    return res.json({ success:false });
  }

  const amountNum = Number(amount);

  if(!name || !amount || !transaction_id){
    return res.json({ success:false, message:"All fields required" });
  }

  if(isNaN(amountNum) || amountNum <= 0){
    return res.json({ success:false, message:"Invalid amount" });
  }

  if(amountNum < 20 || amountNum > 1000){
    return res.send("Amount must be between 20-1000");
  }

  const userData = await pool.query(
    "SELECT email FROM users WHERE id=$1",
    [req.session.userId]
  );

  if(userData.rows.length === 0){
    return res.json({ success:false });
  }

  const email = userData.rows[0].email;

  await pool.query(`
    INSERT INTO payment_requests (name,email,amount,transaction_id,status)
    VALUES ($1,$2,$3,$4,'pending')
  `,[name,email,amountNum,transaction_id]);

  res.json({ success:true, message:"Payment request submitted" });
});

/* WITHDRAW */
app.post("/requestWithdraw", csrfProtection, withdrawLimiter, async (req,res)=>{
  const name = cleanInput(req.body.name);
const amount = req.body.amount;
const upi_id = cleanInput(req.body.upi_id);
  if(!isValidNumber(amount, 200, 100000)){
  return res.send("Invalid amount");
}
if(!req.session.userId){
  return res.send("Not logged in");
}

if(amount <= 0){
  return res.send("Invalid amount");
}
  if(!name || !amount || !upi_id){
    return res.send("All fields required");
  }

  if(amount < 200){
  return res.send("Minimum withdraw is 200");
}

  const userData = await pool.query(
  "SELECT email, balance, bonus FROM users WHERE id=$1",
  [req.session.userId]
);

if(userData.rows.length === 0){
  return res.send("User not found");
}

const email = userData.rows[0].email;
let balance = userData.rows[0].balance;
let bonus = userData.rows[0].bonus;

  

  let withdrawable = balance - bonus;

  if(amount > withdrawable){
    return res.send("You cannot withdraw bonus amount.");
  }

  // 🔒 monthly limit
  const count = await pool.query(
    `SELECT COUNT(*) FROM withdraw_requests 
     WHERE email=$1 AND DATE_TRUNC('month', created_at)=DATE_TRUNC('month', NOW())`,
    [email]
  );

  if(parseInt(count.rows[0].count) >= 12){
    return res.send("Limit reached (12/month)");
  }

  // 💸 charges (CORRECT PLACE)
  let charge = 0;

  if(amount <= 500){
    charge = 20;
  }else if(amount <= 1000){
    charge = 30;
  }else{
    charge = 0;
  }

  let finalAmount = amount - charge;

  if(finalAmount <= 0){
    return res.send("Invalid withdraw amount");
  }

  // ✅ INSERT AFTER CALCULATION
  await pool.query(`
    INSERT INTO withdraw_requests (name,email,amount,charge,final_amount,upi_id,status)
    VALUES ($1,$2,$3,$4,$5,$6,'pending')
  `,[name,email,amount,charge,finalAmount,upi_id]);

  res.send("Withdraw request submitted");
});

/* REQUEST LISTS */
app.get("/paymentRequests", isMainAdmin, async (req,res)=>{
  const result = await pool.query(
    "SELECT * FROM payment_requests WHERE status='pending'"
  );
  res.json(result.rows);
});

app.get("/withdrawRequests", isMainAdmin, async (req,res)=>{
  const result = await pool.query(
    "SELECT * FROM withdraw_requests WHERE status='pending'"
  );
  res.json(result.rows);
});

/* APPROVALS */
app.post("/approvePayment", csrfProtection, isMainAdmin, async (req,res)=>{
  const { id } = req.body;
if(!isValidId(id)){
  return res.send("Invalid ID");
}
  const client = await pool.connect();

try {
  await client.query("BEGIN");

  const request = await client.query(
    "SELECT * FROM payment_requests WHERE id=$1",
    [id]
  );

  if(request.rows.length === 0){
    await client.query("ROLLBACK");
    return res.send("Invalid request");
  }

  const data = request.rows[0];

  await client.query(
    "UPDATE users SET balance = balance + $1 WHERE email=$2",
    [data.amount, data.email]
  );

  await client.query(
    "UPDATE payment_requests SET status='approved' WHERE id=$1",
    [id]
  );

  await client.query("COMMIT");

  res.send("Payment approved");

} catch(err){
  await client.query("ROLLBACK");
  if(process.env.NODE_ENV !== "production"){
  console.error(err);
}
  res.send("Error");
} finally {
  client.release();
}
});

app.post("/approveWithdraw", csrfProtection, isMainAdmin, async (req,res)=>{
  const { id } = req.body;

 const client = await pool.connect();

try {
  await client.query("BEGIN");

  const request = await client.query(
    "SELECT * FROM withdraw_requests WHERE id=$1",
    [id]
  );

  if(request.rows.length === 0){
    await client.query("ROLLBACK");
    return res.send("Invalid request");
  }

  const data = request.rows[0];

  await client.query(
    "UPDATE users SET balance = balance - $1 WHERE email=$2",
    [data.amount, data.email]
  );

  await client.query(
    "UPDATE withdraw_requests SET status='approved' WHERE id=$1",
    [id]
  );

  await client.query("COMMIT");

  res.send("Withdraw approved");

} catch(err){
  await client.query("ROLLBACK");
  if(process.env.NODE_ENV !== "production"){
  console.error(err);
}
  res.send("Error");
} finally {
  client.release();
}
});

/* BALANCE */
app.get("/balance", isLoggedIn, async (req,res)=>{
  if(!req.session.userId){
    return res.json({balance:0});
  }

  const result = await pool.query(
    "SELECT balance FROM users WHERE id=$1",
    [req.session.userId]
  );

  res.json(result.rows[0]);
});

/* ✅ PLACE BET (FIXED) */
app.post("/placeBet", csrfProtection, strictLimiter, isLoggedIn, async (req,res)=>{
  try {

    let amount = req.body.amount;
let team = req.body.team;

let match_id = req.body.match_id;
let type = req.body.type;
let player_name = cleanInput(req.body.player_name);
let bet_category = cleanInput(req.body.bet_category);
const matchData = await pool.query(
  "SELECT team1_odds, team2_odds FROM matches WHERE id=$1",
  [match_id]
);

if(matchData.rows.length === 0){
  return res.json({success:false});
}

let odds;

// 🎯 PLAYER BET → get odds from DB
if(bet_category === "top_scorer" || bet_category === "top_wicket"){
const matchStatus = await pool.query(
  "SELECT scorer_open, wicket_open FROM matches WHERE id=$1",
  [match_id]
);

if(bet_category === "top_scorer" && !matchStatus.rows[0].scorer_open){
  return res.json({success:false, msg:"Scorer closed"});
}

if(bet_category === "top_wicket" && !matchStatus.rows[0].wicket_open){
  return res.json({success:false, msg:"Wicket closed"});
}
  const playerData = await pool.query(
    `SELECT odds FROM player_bets 
     WHERE match_id=$1 AND player_name=$2`,
    [match_id, player_name]
  );

  if(playerData.rows.length === 0){
    return res.json({ success:false });
  }

  odds = playerData.rows[0].odds;
}

// 🏏 NORMAL MATCH BET
// 🎯 PLAYER BET → DO NOTHING (keep DB odds)
if(bet_category === "top_scorer" || bet_category === "top_wicket"){
  // already set above → DO NOT override
}

// ⚡ RAPID → always 10x
else if(type === "rapid"){
  odds = 10;
}

// 🪙 TOSS
else if(type === "toss"){
  odds = 1.4;
}

// 🏏 NORMAL MATCH
else{
  if(team == 1){
    odds = matchData.rows[0].team1_odds;
  }else{
    odds = matchData.rows[0].team2_odds;
  }
}

    if(!isValidNumber(amount, 1, 10000)){
  return res.json({success:false});
}

if(!isValidId(match_id)){
  return res.json({success:false});
}

if(team != 1 && team != 2){
  return res.json({success:false});
}
    const matchCheck = await pool.query(
"SELECT match_open FROM matches WHERE id=$1",
[match_id]
);

if(type === "normal" && !matchCheck.rows[0].match_open){
  return res.json({success:false});
}
    if(type === "rapid"){

const match = await pool.query(
"SELECT rapid_open FROM matches WHERE id=$1",
[match_id]
);

if(!match.rows[0].rapid_open){
return res.json({success:false});
}

}
    // 👇 ADD THIS BLOCK
if(type === "toss"){

const match = await pool.query(
"SELECT toss_open FROM matches WHERE id=$1",
[match_id]
);

if(!match.rows[0].toss_open){
return res.json({success:false});
}

}

    if(!req.session.userId){
      return res.json({success:false});
    }
if(type === "toss"){
  odds = 1.4;
}
// 🚫 prevent spam betting (2 sec cooldown)
const lastBet = await pool.query(
  "SELECT created_at FROM bets WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1",
  [req.session.userId]
);

if(lastBet.rows.length > 0){
  const lastTime = new Date(lastBet.rows[0].created_at).getTime();

  if(Date.now() - lastTime < 2000){
    return res.json({success:false, msg:"Too fast"});
  }
}
   

    // ✅ CORRECT INSERT
   let finalType = "normal";

// 🪙 toss
if(type === "toss"){
  finalType = "toss";
}

// ⚡ rapid
else if(type === "rapid"){
  finalType = "rapid";
}

// 🎯 player bets
else if(bet_category === "top_scorer" || bet_category === "top_wicket"){
  finalType = "player";
}

// 🏏 default
else{
  finalType = "normal";
}

const client = await pool.connect();

try{

  await client.query("BEGIN");
await client.query(
  "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
  [req.session.userId]
);
  // 1. deduct balance safely
  const result = await client.query(
    `UPDATE users 
     SET balance = balance - $1 
     WHERE id = $2 AND balance >= $1 
     RETURNING balance`,
    [amount, req.session.userId]
  );

  if(result.rowCount === 0){
    await client.query("ROLLBACK");
    return res.json({success:false});
  }

  // 2. insert bet
  await client.query(`
    INSERT INTO bets 
    (user_id, match_id, team, amount, odds, type, player_name, bet_category)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
  `,[
    req.session.userId,
    match_id,
    team,
    amount,
    odds,
    finalType,
    player_name || null,
    bet_category || null
  ]);

  await client.query("COMMIT");

  return res.json({
  success: true,
  role: "main"
});

}catch(err){

  await client.query("ROLLBACK");
  if(process.env.NODE_ENV !== "production"){
  console.error(err);
}
  return res.json({success:false});

}finally{
  client.release();
}


} catch(err){
  if(process.env.NODE_ENV !== "production"){
  console.error(err);
}
  res.json({success:false});
}
});
/* ✅ GET BETS */
app.get("/bets", isLoggedIn, async (req,res)=>{

  if(!req.session.userId){
    return res.json([]);
  }

  const result = await pool.query(`
  SELECT 
  b.*, 
  t1.name AS team1_name, t1.logo AS team1_logo,
  t2.name AS team2_name, t2.logo AS team2_logo, m.match_date
  FROM bets b
LEFT JOIN matches m ON b.match_id = m.id
LEFT JOIN teams t1 ON m.team1_id = t1.id
LEFT JOIN teams t2 ON m.team2_id = t2.id
  WHERE b.user_id=$1
  ORDER BY b.id DESC
  `,[req.session.userId]);

  res.json(result.rows);
});
app.post("/setResult", csrfProtection, isMainAdmin, async (req,res)=>{

const { match_id, winner, type, top_scorer, top_wicket } = req.body;
const client = await pool.connect();
try{

  await client.query("BEGIN");
// ✅ SAVE WINNER ONLY FOR MATCH (normal)
if(type === "normal"){
  await client.query(
    "UPDATE matches SET winner=$1 WHERE id=$2",
    [winner, match_id]
  );
}

// ✅ GET ONLY RELEVANT BETS
const bets = await client.query(
  "SELECT * FROM bets WHERE match_id=$1 AND type=$2",
  [match_id, type]
);

for(let bet of bets.rows){

  if(bet.status !== "pending") continue;

  let isWin = false;

  // 🏏 NORMAL MATCH
  if(type === "normal"){
    if(bet.team == winner){
      isWin = true;
    }
  }

  // ⚡ RAPID
  else if(type === "rapid"){
    if(bet.team == winner){
      isWin = true;
    }
  }

  // 🪙 TOSS
  else if(type === "toss"){
    if(bet.team == winner){
      isWin = true;
    }
  }

  // 🎯 PLAYER BETS
  else if(type === "player"){

    if(bet.bet_category === "top_scorer" && bet.player_name == top_scorer){
      isWin = true;
    }

    if(bet.bet_category === "top_wicket" && bet.player_name == top_wicket){
      isWin = true;
    }

  }

  // ✅ FINAL SETTLEMENT
  if(isWin){

    let latestOdds;

// get latest odds from match table
const matchData = await client.query(
  "SELECT team1_odds, team2_odds FROM matches WHERE id=$1",
  [match_id]
);

if(type === "normal"){
  if(bet.team == 1){
    latestOdds = matchData.rows[0].team1_odds;
  }else{
    latestOdds = matchData.rows[0].team2_odds;
  }
}else{
  // fallback for other types
  latestOdds = bet.odds;
}

let payout = Math.floor(bet.amount * latestOdds);

    await client.query(
      "UPDATE users SET balance = balance + $1 WHERE id=$2",
      [payout, bet.user_id]
    );

    await client.query(
      "UPDATE bets SET status='won', payout=$1 WHERE id=$2",
      [payout, bet.id]
    );

  }else{

    await client.query(
      "UPDATE bets SET status='lost' WHERE id=$1",
      [bet.id]
    );

  }

}

await client.query("COMMIT");

res.send("✅ Result declared for " + type);

}catch(err){

  await client.query("ROLLBACK");
  if(process.env.NODE_ENV !== "production"){
  console.error(err);
}
  res.send("Error setting result");

}
finally{
  client.release();
}
});
app.post("/signup", csrfProtection, loginLimiter, async (req, res) => {
  const name = cleanInput(req.body.name);
const email = cleanInput(req.body.email).toLowerCase();
const password = req.body.password; // ❗ don't touch password
const referral_code = cleanInput(req.body.referral_code);
// ❌ invalid email
if(!validator.isEmail(email)){
  return res.json({ success:false, message:"Invalid email" });
}

// ❌ weak password
if(
  password.length < 8 ||
  !/[A-Z]/.test(password) ||
  !/[a-z]/.test(password) ||
  !/[0-9]/.test(password)
){
  return res.json({
    success:false,
    message:"Password must be 8+ chars with uppercase, lowercase, and number"
  });
}

// ❌ name check
if(!name || name.length < 2){
  return res.send("Invalid name");
}
  if(!name || !email || !password){
    return res.send("All fields required");
  }

  try{

    let adminId = null;
// 🔒 check if email already exists
const existingUser = await pool.query(
  "SELECT id FROM users WHERE email=$1",
  [email]
);

if(existingUser.rows.length > 0){
  return res.json({ success:false, message:"Email already registered" });
}
    // 🔗 check referral code
   if(referral_code){

  const admin = await pool.query(
    "SELECT id, is_blocked FROM admin_users WHERE referral_code=$1",
    [referral_code]
  );

  if(admin.rows.length > 0){

    // 🚫 if blocked → stop signup
    if(admin.rows[0].is_blocked){
      return res.send("This referral is blocked");
    }

    // ✅ if not blocked → allow
    adminId = admin.rows[0].id;
  }

}

   const hashedPassword = await bcrypt.hash(password, 10);

await pool.query(
  "INSERT INTO users (name, email, password, balance, minor_admin_id) VALUES ($1,$2,$3,0,$4)",
  [name, email, hashedPassword, adminId]
);

    res.json({ success: true });

 } catch(err){
  console.error("SIGNUP ERROR:", err); // keep this ALWAYS

  res.status(500).json({
    success: false,
    message: "Signup error"
  });
}
});
app.get("/walletHistory", isLoggedIn, async (req,res)=>{

  if(!req.session.userId){
    return res.json([]);
  }

  const user = await pool.query(
    "SELECT email FROM users WHERE id=$1",
    [req.session.userId]
  );

  const email = user.rows[0].email;

  const payments = await pool.query(
    "SELECT amount, status, created_at FROM payment_requests WHERE email=$1",
    [email]
  );

  const withdraws = await pool.query(
  "SELECT amount, charge, final_amount, status, created_at FROM withdraw_requests WHERE email=$1",
  [email]
);

  let history = [];

  payments.rows.forEach(p=>{
    history.push({
      type:"add",
      amount:p.amount,
      status: p.status || "pending",// pending OR approved
      date:p.created_at
    });
  });

  withdraws.rows.forEach(w=>{
  history.push({
    type:"withdraw",
    amount:w.amount,
    charge: w.charge || 0,
    final: w.final_amount || w.amount,
    status:w.status,
    date:w.created_at
  });
});

  // ✅ SORT LATEST FIRST
  history.sort((a,b)=> new Date(b.date) - new Date(a.date));

  res.json(history);
});
app.get("/bonusStatus", (req,res)=>{
  if(req.session.showBonus){
    req.session.showBonus = false; // show only once
    return res.json({show:true});
  }
  res.json({show:false});
});
app.get("/debug/users", isDeveloper, async (req,res)=>{
  const data = await pool.query("SELECT * FROM users");
  res.json(data.rows);
});
function generateCode(length = 6) {
  return Math.random().toString(36).substring(2, 2 + length);
}

app.post("/createSubAdmin", csrfProtection, isMainAdmin, async (req,res)=>{

  const username = "admin_" + generateCode(5);
  const rawPassword = generateCode(8);
  const hashedPassword = await bcrypt.hash(rawPassword, 10);
  const referral = generateCode(6);

  try{

    await pool.query(
      "INSERT INTO admin_users (username,password,referral_code) VALUES ($1,$2,$3)",
      [username,hashedPassword,referral]
    );

    res.json({username, password: rawPassword, referral});

  }catch(err){
    if(process.env.NODE_ENV !== "production"){
  console.error(err);
}
    res.send("Error creating admin");
  }

});
function generateCode(length = 6) {
  return crypto.randomBytes(length)
    .toString("base64")
    .replace(/[^a-zA-Z0-9]/g, "") // clean symbols
    .substring(0, length);
}

app.get("/adminStats", isMainAdmin, async (req,res)=>{

// 1. get all minor admins
const admins = await pool.query("SELECT * FROM admin_users");

let result = [];

for(let a of admins.rows){

  // 2. get users of this admin
  const users = await pool.query(
    "SELECT id,name,email,balance FROM users WHERE minor_admin_id=$1",
    [a.id]
  );

  let userData = [];

  for(let u of users.rows){

    // 3. get bets of each user
    const bets = await pool.query(`
SELECT 
b.*,
m.id as match_id,
t1.name as team1,
t2.name as team2
FROM bets b
LEFT JOIN matches m ON b.match_id = m.id
LEFT JOIN teams t1 ON m.team1_id = t1.id
LEFT JOIN teams t2 ON m.team2_id = t2.id
WHERE b.user_id=$1
ORDER BY b.created_at DESC
`,[u.id]);

    userData.push({
      ...u,
      bets: bets.rows
    });

  }

  result.push({
    admin:a,
    users:userData
  });

}

// 4. send everything
res.json(result);

});
app.post("/blockAdmin", csrfProtection, isMainAdmin, async (req,res)=>{
  const { id } = req.body;

  await pool.query(
    "UPDATE admin_users SET is_blocked = NOT is_blocked WHERE id=$1",
    [id]
  );

  res.send("Admin status toggled");
});

app.post("/deleteAdmin", csrfProtection, isMainAdmin, async (req,res)=>{
  const { id } = req.body;

  // unlink users first
  await pool.query(
    "UPDATE users SET minor_admin_id=NULL WHERE minor_admin_id=$1",
    [id]
  );

  // delete admin
  await pool.query(
    "DELETE FROM admin_users WHERE id=$1",
    [id]
  );

  res.send("Admin deleted");
});
app.post("/adminLogin", csrfProtection, loginLimiter, async (req,res)=>{

  const { username, password } = req.body;

  const admin = await pool.query(
    "SELECT * FROM admin_users WHERE username=$1",
    [username]
  );

  if(admin.rows.length === 0){
    return res.json({success:false});
  }

  if(admin.rows[0].is_blocked){
    return res.json({success:false});
  }

  const match = await bcrypt.compare(password, admin.rows[0].password);

  if(!match){
    return res.json({success:false});
  }

 req.session.regenerate((err) => {
  if(err){
    return res.json({success:false});
  }

  req.session.adminId = admin.rows[0].id;
  req.session.isMainAdmin = false;
  req.session.isMinorAdmin = true;

  // ✅ FIX HERE ALSO
  req.session.save((err) => {
    if(err){
      return res.json({success:false});
    }

    res.json({
      success: true,
      role: "minor"
    });
  });
});
});
app.get("/minorAdminData", async (req,res)=>{

if(!req.session.adminId){
  return res.json({error:"Not logged in"});
}

const adminId = req.session.adminId;

// 1. get users of this admin
const users = await pool.query(
  "SELECT id,name,email,balance FROM users WHERE minor_admin_id=$1",
  [adminId]
);

let userData = [];
let totalLoss = 0;

for(let u of users.rows){

  const bets = await pool.query(
    "SELECT status,amount,payout FROM bets WHERE user_id=$1",
    [u.id]
  );

  let userLoss = 0;

  bets.rows.forEach(b => {

    if(b.status === "lost"){
      userLoss += b.amount;   // ✅ ADD LOSS
    }

    

  });

  totalLoss += userLoss;

  userData.push({
    ...u,
    loss:userLoss
  });

}

// 2. earnings = 30% of losses
let earnings = Math.floor(totalLoss * 0.3);

res.json({
  users:userData,
  totalLoss,
  earnings
});

});
app.get("/adminLogout", (req,res)=>{
  req.session.destroy(()=>{
    res.send("Logged out");
  });
});
app.post("/openRapid", csrfProtection, isMainAdmin, async (req,res)=>{
const { team } = req.body;

// 🔍 get featured match automatically
const result = await pool.query(
"SELECT id FROM matches WHERE status='featured' LIMIT 1"
);

if(result.rows.length === 0){
  return res.send("No featured match");
}

let match_id = result.rows[0].id;

// ✅ update featured match
await pool.query(
"UPDATE matches SET rapid_open=true, rapid_team=$1 WHERE id=$2",
[team, match_id]
);

res.send("Rapid Bet Opened 🚀");

});
app.post("/closeRapid", csrfProtection, isMainAdmin, async (req,res)=>{

await pool.query(
"UPDATE matches SET rapid_open=false WHERE status='featured'"
);

res.send("Rapid Closed");

});
app.post("/rapidBet", csrfProtection, strictLimiter, loginLimiter, isLoggedIn, async (req,res)=>{

const team = Number(req.body.team);
const match_id = Number(req.body.match_id);
const amount = Number(req.body.amount);

if(!isValidId(match_id) || !isValidNumber(amount, 1, 10000)){
  return res.json({success:false});
}

if(team !== 1 && team !== 2){
  return res.json({success:false});
}

const client = await pool.connect();

try {
  await client.query("BEGIN");
await client.query(
  "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
  [req.session.userId]
);
  const result = await client.query(
    `UPDATE users 
     SET balance = balance - $1 
     WHERE id = $2 AND balance >= $1 
     RETURNING balance`,
    [amount, req.session.userId]
  );

  if(result.rowCount === 0){
    await client.query("ROLLBACK");
    return res.json({success:false});
  }

  await client.query(
    "INSERT INTO bets (user_id, match_id, team, amount, odds) VALUES ($1,$2,$3,$4,10)",
    [req.session.userId, match_id, team, amount]
  );

  await client.query("COMMIT");

  res.json({success:true});

} catch(err){
  await client.query("ROLLBACK");
  if(process.env.NODE_ENV !== "production"){
  console.error(err);
}
  res.json({success:false});
} finally {
  client.release();
}

});
app.get("/debug/all", isDeveloper, async (req, res) => {
  const users = await pool.query("SELECT * FROM users");
  const bets = await pool.query("SELECT * FROM bets");
  const matches = await pool.query("SELECT * FROM matches");
  const teams = await pool.query("SELECT * FROM teams");

  res.json({
    users: users.rows,
    bets: bets.rows,
    matches: matches.rows,
    teams: teams.rows
  });
});
// OPEN TOSS
app.post("/openToss", csrfProtection, isMainAdmin, async (req,res)=>{

const match = await pool.query("SELECT id FROM matches WHERE status='featured' LIMIT 1");

await pool.query("UPDATE matches SET toss_open=true WHERE id=$1",[match.rows[0].id]);

res.send("Toss opened");

});

// SET TOSS RESULT
app.post("/setTossWinner", csrfProtection, isMainAdmin, async (req,res)=>{

const { match_id, winner } = req.body;

await pool.query(
"UPDATE matches SET toss_open=false, toss_winner=$1 WHERE id=$2",
[winner, match_id]
);

const bets = await pool.query(
"SELECT * FROM bets WHERE match_id=$1 AND type='toss'",
[match_id]
);

for(let b of bets.rows){

if(b.team == winner){

let payout = Math.floor(b.amount * 1.4);

await pool.query("UPDATE users SET balance=balance+$1 WHERE id=$2",[payout,b.user_id]);

await pool.query("UPDATE bets SET status='won', payout=$1 WHERE id=$2",[payout,b.id]);

}else{

await pool.query("UPDATE bets SET status='lost' WHERE id=$1",[b.id]);

}

}

res.send("Toss result done");

});
app.post("/closeToss", csrfProtection, isMainAdmin, async (req,res)=>{

await pool.query(
"UPDATE matches SET toss_open=false WHERE status='featured'"
);

res.send("Toss closed");

});
app.post("/openMatch", csrfProtection, isMainAdmin, async (req,res)=>{

await pool.query(
"UPDATE matches SET match_open=true WHERE status='featured'"
);

res.send("Match opened");

});
app.post("/closeMatch", csrfProtection, isMainAdmin, async (req,res)=>{

await pool.query(
"UPDATE matches SET match_open=false WHERE status='featured'"
);

res.send("Match closed");

});
app.post("/updateOdds", csrfProtection, isMainAdmin, async (req,res)=>{

const { team1Odds, team2Odds } = req.body;

try{

await pool.query(
"UPDATE matches SET team1_odds=$1, team2_odds=$2 WHERE status='featured'",
[team1Odds, team2Odds]
);

res.send("Odds updated ✅");

}catch(err){
if(process.env.NODE_ENV !== "production"){
  console.error(err);
}
res.send("Error updating odds");
}

});
app.post("/sendOtp", csrfProtection, otpSendLimiter, async (req,res)=>{

const email = req.body.email.trim().toLowerCase();

// ✅ check valid email format
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

if(!emailRegex.test(email)){
  return res.json({success:false, message:"Invalid email format"});
}
const existing = await pool.query(
  "SELECT * FROM otp_codes WHERE email=$1",
  [email]
);

if(existing.rows.length > 0){
  const expiresAt = new Date(existing.rows[0].expires_at).getTime();

  if(Date.now() < expiresAt - (4 * 60 * 1000)){
    return res.json({success:true});
  }
}
const rawOtp = Math.floor(100000 + Math.random() * 900000).toString();
const hashedOtp = await bcrypt.hash(rawOtp, 10);

// ⏳ expires in 5 minutes
const expires = Date.now() + (5 * 60 * 1000);

// upsert (insert or update)
await pool.query(`
  INSERT INTO otp_codes (email, otp, expires_at, attempts)
  VALUES ($1,$2,$3,0)
  ON CONFLICT (email)
  DO UPDATE SET otp=$2, expires_at=$3, attempts=0
`, [email, hashedOtp, expires]);

try {
  await transporter.sendMail({
    from: process.env.EMAIL_USER,   // ✅ FIX HERE
    to: email,
    subject: "OTP Verification",
    text: `Your OTP is ${rawOtp}`
  });
} catch (err) {
  console.error("MAIL ERROR:", err);
  return res.status(500).json({
    success: false,
    message: "Email failed"
  });
}

res.json({success:true});

});
app.post("/verifyOtp", csrfProtection, otpVerifyLimiter, async (req,res)=>{

  const email = req.body.email.trim().toLowerCase();
const otp = req.body.otp;

  const result = await pool.query(
  "SELECT * FROM otp_codes WHERE email=$1",
  [email]
);

const record = result.rows[0];

  // ❌ no OTP found
  if(!record){
    return res.json({success:false, msg:"No OTP found"});
  }

  // ⏳ expired
  if(Date.now() > record.expires_at){
   await pool.query("DELETE FROM otp_codes WHERE email=$1", [email]);
    return res.json({success:false, msg:"OTP expired"});
  }

  // 🚫 too many attempts
  if(record.attempts >= 5){
    await pool.query("DELETE FROM otp_codes WHERE email=$1", [email]);
    return res.json({success:false, msg:"Too many attempts"});
  }

  // ❌ wrong OTP
  const isMatch = await bcrypt.compare(otp, record.otp);

if(!isMatch){
  await pool.query(
    "UPDATE otp_codes SET attempts = attempts + 1 WHERE email=$1",
    [email]
  );
  return res.json({success:false, msg:"Invalid OTP"});
}

  // ✅ success → delete OTP (one-time use)
  await pool.query("DELETE FROM otp_codes WHERE email=$1", [email]);

  return res.json({success:true});
});
app.get("/debug/simpleTeams", isDeveloper, async (req,res)=>{

  const teams = await pool.query("SELECT * FROM teams");

  let output = "";

  for(let t of teams.rows){

    const players = await pool.query(
      "SELECT name FROM players WHERE team_id=$1",
      [t.id]
    );

    let names = players.rows.map(p => p.name).join(", ");

    output += `${t.name} - ${names}\n\n`;
  }

  res.send(`<pre>${output}</pre>`); // keeps formatting
});
app.get("/playerBets", async (req,res)=>{
  try{

    const match = await pool.query(
      "SELECT id FROM matches WHERE status='featured' ORDER BY id DESC LIMIT 1"
    );

    if(match.rows.length === 0){
      return res.json([]);
    }

    const match_id = match.rows[0].id;

    const result = await pool.query(
      "SELECT * FROM player_bets WHERE match_id=$1",
      [match_id]
    );

    res.json(result.rows);

  }catch(err){
    if(process.env.NODE_ENV !== "production"){
  console.error(err);
}
    res.json([]);
  }
});
app.get("/playersByTeams", async (req,res)=>{
  const { team1, team2 } = req.query;

  try{
    const result = await pool.query(
      "SELECT id, name, team_id FROM players WHERE team_id IN ($1,$2)",
      [team1, team2]
    );

    res.json(result.rows);

  }catch(err){
    if(process.env.NODE_ENV !== "production"){
  console.error(err);
}
    res.json([]);
  }
});
app.get("/sessionQuestions", async (req,res)=>{

// get teams for tournament options
const teams = await pool.query("SELECT id,name FROM teams");

let result = sessionQuestions.map(q=>{

let options = q.options;

// 🏆 tournament → use team names
if(q.type === "tournament"){
  options = teams.rows.map(t=>t.name);
}

return {
  ...q,
  options
};

});

res.json(result);

});
app.post("/placeSessionBet", csrfProtection, strictLimiter, isLoggedIn, async (req,res)=>{

try{

const question_id = Number(req.body.question_id);
const choice = cleanInput(req.body.choice);
const amount = Number(req.body.amount);

// validation
if(!isValidId(question_id) || !isValidNumber(amount, 20, 10000)){
  return res.json({success:false});
}

if(!req.session.userId){
  return res.json({success:false});
}

if(amount < 20){
  return res.json({success:false});
}

// find question
let q = sessionQuestions.find(x=>x.id == question_id);

if(!q || !q.is_open){
  return res.json({success:false});
}

// ❗ one bet rule
if(q.oneBet){
  const check = await pool.query(
    "SELECT * FROM bets WHERE user_id=$1 AND session_question_id=$2",
    [req.session.userId, question_id]
  );

  if(check.rows.length > 0){
    return res.json({success:false, msg:"Max bet reached for tournament sessions!"});
  }
}

// 🔒 START TRANSACTION
const client = await pool.connect();

try{

  await client.query("BEGIN");

  // 🔒 LOCK USER ROW
  await client.query(
    "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
    [req.session.userId]
  );

  // 💰 SAFE BALANCE UPDATE
  const result = await client.query(
    `UPDATE users 
     SET balance = balance - $1 
     WHERE id = $2 AND balance >= $1 
     RETURNING balance`,
    [amount, req.session.userId]
  );

  if(result.rowCount === 0){
    await client.query("ROLLBACK");
    client.release();
    return res.json({success:false});
  }

  // match teams
  const match = await client.query(
    "SELECT t1.name AS team1, t2.name AS team2 FROM matches m JOIN teams t1 ON m.team1_id=t1.id JOIN teams t2 ON m.team2_id=t2.id WHERE m.status='featured' LIMIT 1"
  );

  let team1 = match.rows[0]?.team1 || "";
  let team2 = match.rows[0]?.team2 || "";

  // insert bet
  await client.query(`
    INSERT INTO bets 
    (user_id, amount, odds, type, status, session_question_id, session_choice, question_text, match_team1, match_team2)
    VALUES ($1,$2,$3,'session','pending',$4,$5,$6,$7,$8)
  `,[
    req.session.userId,
    amount,
    q.odds,
    question_id,
    choice,
    q.question,
    team1,
    team2
  ]);

  // ✅ COMMIT
  await client.query("COMMIT");
  client.release();

  return res.json({success:true});

}catch(err){

  await client.query("ROLLBACK");
  client.release();

  if(process.env.NODE_ENV !== "production"){
    console.error(err);
  }

  return res.json({success:false});
}

}catch(err){
  if(process.env.NODE_ENV !== "production"){
    console.error(err);
  }
  res.json({success:false});
}

});
app.get("/sessionBets", isLoggedIn, async (req,res)=>{

if(!req.session.userId){
  return res.json([]);
}

const result = await pool.query(
"SELECT * FROM bets WHERE user_id=$1 AND type='session' AND status='pending'",
[req.session.userId]
);

res.json(result.rows);

});
app.post("/setSessionResult", csrfProtection, isMainAdmin, async (req,res)=>{

const { question_id, correct } = req.body;

let q = sessionQuestions.find(x=>x.id == question_id);

if(!q) return res.send("Invalid");

// save correct answer
q.correct = correct;
q.is_open = false;

// get bets
const bets = await pool.query(
"SELECT * FROM bets WHERE session_question_id=$1 AND status='pending'",
[question_id]
);

for(let b of bets.rows){

let isWin = b.session_choice === correct;

if(isWin){

let payout = Math.floor(b.amount * b.odds);

await pool.query(
"UPDATE users SET balance=balance+$1 WHERE id=$2",
[payout, b.user_id]
);

await pool.query(
"UPDATE bets SET status='won', payout=$1 WHERE id=$2",
[payout, b.id]
);

}else{

await pool.query(
"UPDATE bets SET status='lost' WHERE id=$1",
[b.id]
);

}

}

res.send("Session settled ✅");

});
app.post("/toggleSession", csrfProtection, isMainAdmin, (req,res)=>{

const { question_id } = req.body;

let q = sessionQuestions.find(x=>x.id == question_id);

if(!q) return res.send("Invalid");

q.is_open = !q.is_open;

res.send("Toggled");

});
app.get("/allUsers", isMainAdmin, async (req,res)=>{

  const result = await pool.query(
    "SELECT name, email FROM users ORDER BY id DESC"
  );

  res.json(result.rows);

});


app.post("/mainAdminLogin", csrfProtection, loginLimiter, async (req,res)=>{
const { username, password } = req.body;
  if(username !== process.env.MAIN_ADMIN_USER){
    return res.json({success:false});
  }

  const match = await bcrypt.compare(password, process.env.MAIN_ADMIN_PASS);

  if(!match){
    return res.json({success:false});
  }

  // 🔒 regenerate session (IMPORTANT)
 req.session.regenerate((err) => {
  if(err){
    return res.json({success:false});
  }

  req.session.isMainAdmin = true;

  // ✅ ADD THIS BLOCK
  req.session.save((err) => {
    if(err){
      return res.json({success:false});
    }

    return res.json({success:true});
  });

});

});

app.post("/togglePlayerMarket", csrfProtection, isMainAdmin, async (req,res)=>{

  const { type, status } = req.body;

  const match = await pool.query(
    "SELECT id FROM matches WHERE status='featured' LIMIT 1"
  );

  if(match.rows.length === 0){
    return res.json({success:false});
  }

  let match_id = match.rows[0].id;

  if(type === "scorer"){
    await pool.query(
      "UPDATE matches SET scorer_open=$1 WHERE id=$2",
      [status, match_id]
    );
  }

  if(type === "wicket"){
    await pool.query(
      "UPDATE matches SET wicket_open=$1 WHERE id=$2",
      [status, match_id]
    );
  }

  res.json({success:true});
});

function isDeveloper(req,res,next){

  // allow only from your own computer
  if(req.ip === "::1" || req.ip === "127.0.0.1"){
    return next();
  }

  return res.status(403).json({success:false, message:"Not allowed"});
}
app.get("/logout", (req,res)=>{
  req.session.destroy(()=>{
    res.send("Logged out");
  });
});

app.use((err, req, res, next) => {

  if(err.code === "EBADCSRFTOKEN"){
    return res.status(403).json({success:false, message:"Invalid CSRF token"});
  }

  if(process.env.NODE_ENV !== "production"){
  console.error(err.stack);
}
  res.status(500).json({success:false});
});
app.listen(3000, () => {
  if(process.env.NODE_ENV !== "production"){
  console.log("Server running on port 3000");
}
});