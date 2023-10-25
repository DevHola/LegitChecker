const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { check, body, validationResult } = require('express-validator');
const multer = require('multer');
const path = require('path');
const fs = require('fs')
const natural = require('natural');
const Minhash = require('minhash');
const jaccard = require('jaccard');
const stopword = require('stopword');
const pdfjs = require('pdfjs-dist');
const stringSimilarity = require('string-similarity');
const speakeasy = require("@levminer/speakeasy")
const crypto = require('crypto')
const cors = require('cors')
const morgan = require('morgan')
const mail = require('./mail')
const dotenv = require('dotenv').config()

const app = express();
const port = process.env.PORT;
// TODO: User Account Creation . done
// TODO: User Authentication . done
// TODO: Profile Creation , img upload and verification otp gen and mail . done
// TODO: verification of otp . done
// TODO: Bill Creation and upload . done
// TODO: Plargarism Detection . Submitting an old document using a new name . done
// TODO: allow admin to do Account Approval . PENDING
// TODO: Modify Login to work only if user is approved and verified . done
// TODO: Allow user to edit certain details in profile . PENDING

// Connect to MongoDB
const db = require('./db');

// Define MongoDB Schema
const User = mongoose.model('User', {
  username: String,
  password: String,
  role: {
    type:String,
    enum: ['basic', 'admin', 'super-admin'],
    default:'basic'
  },
  isVerified: {
    type:Boolean,
    default:false
  },
  isApproved: {
    type: Boolean,
    default:false
  },
  restToken:  {
    type:String,
    default:null
  },
  profile:{
    type: mongoose.Schema.Types.ObjectId,
    ref:'Profile'
  },
  otp:{
    type:String,
    default:null
  },
  Regwf:{
    RegisterComplete:{
      type:Boolean,
      default:false
    },
    ProfileComplete:{
      type:Boolean,
      default:false
    },
    VerifiedComplete:{
      type:Boolean,
      default:false
    }
  }
});

const Profile = mongoose.model('Profile',{
  fullname:String,
  State:String,
  Constituency:String,
  phone:Number,
  profilepicture:String,
  positionsheld:String

})

const billSchema = mongoose.model('billSchema',{
    title: String,
    type: String,
    status: {
      type: String,
      default:'Pending'
    },
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    pdfFilePath: String,
    submissionDate: Date, // Add a field to store the submission date
    month: Number, // Add a field to store the month (1 to 12)
    year: Number,  // Add a field to store the year
  });

const plagiarismReport = mongoose.model('plagiarismReport',{
    newdocument_id:{
      type:mongoose.Schema.Types.ObjectId,
      ref:'billSchema'
    } ,
    newDocumentTitle: String,
    similarDocuments: [
      {
        documentId: mongoose.Schema.Types.ObjectId,
        title: String,
        cosineSimilarity: Number,
        jaccardSimilarity: Number
      },
    ],
    timestamp: { type: Date, default: Date.now },
  });
const Mail = mongoose.model('Mail',{
  Email:{
    type:String,
    unique:true,
    required:true
  },
  admin:{
    type:mongoose.Types.ObjectId,
    required:true
  }
})

// Middleware
const corsOptions = {
  origin: 'http://localhost:3000', // Replace with your allowed origin
};

app.use(cors(corsOptions));
app.use(morgan('combined'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use('/uploads', express.static('uploads'));

async function otpgen() {
  let secret = speakeasy.generateSecret({ length: 6 })
  let token = speakeasy.totp({
    secret: secret.base32,
    encoding: "base32",
    time: 640, // specified in seconds
  })
  
  return {
    secret: {
      ascii: secret.ascii,
      hex: secret.hex,
      base32: secret.base32,
    },
    token: token
  }

}

async function verifyotp(secret,otp){
  let tokenValidates = speakeasy.totp.verify({
    secret: secret,
    encoding: "base32",
    token: otp,
    time: 640,
  })
  return tokenValidates

}

async function extractTextFromPDF(pdfFilePath) {
  try {
    // Read the PDF file as a data buffer
    const dataBuffer = fs.readFileSync(pdfFilePath);

    // Convert the Buffer to a Uint8Array
    const dataUint8Array = new Uint8Array(dataBuffer);

    // Load the PDF data Uint8Array using pdfjs-dist
    const pdfDocument = await pdfjs.getDocument(dataUint8Array).promise;

    // Initialize variables to store extracted text
    let text = '';

    // Loop through each page and extract text
    for (let pageNum = 1; pageNum <= pdfDocument.numPages; pageNum++) {
      const page = await pdfDocument.getPage(pageNum);
      const pageText = await page.getTextContent();
      pageText.items.forEach((item) => {
        text += item.str + ' ';
      });
    }

    return text;
  } catch (error) {
    console.error('Error extracting text from PDF:', error);
    throw error;
  }
}
// Authentication Middleware
const authenticateUser = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) {
    return res.status(401).json({ message: 'Access denied' });
  }

  try {
    const decoded = jwt.verify(token, 'secretKey');
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};


const checkUserRole= (allowedRoles) => {
  return (req, res, next) => {
    const uer =[req.user.role]
    const userRoles =  uer // Default to 'basic' role if user not authenticated or roles are not an array
    // Check if any of the user's roles match the allowed roles
    const hasPermission = userRoles.some((role) => allowedRoles.includes(role));

    if (!hasPermission) {
      return res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
    }

    next(); // User has permission, continue to the route handler
  };
}

const emailmatch =async (email)=>{
  const mail = await Mail.findOne({Email:email})
  if (mail){
    return true;
  }else{
    return false
  }
}

//
app.get('/api/validate-token', authenticateUser, (req, res) => {
try {
  const user = req.user;
  res.status(200).json(user);
} catch (error) {
  res.status(500).json({
    message:error
  })
}
});

app.post('/add/email',authenticateUser,checkUserRole(['super-admin','sub-admin']),async (req,res)=>{
  const user = req.user._id;
  const mail = new Mail({
    Email:req.body.email,
    admin: user
  })
 try {
  await mail.save()
  res.status(200).json({
    message:'Added'
  })
 } catch (error) {
  res.status(500).json({
    message:error
  })
 }

})

app.put('/email/:id/edit',authenticateUser,checkUserRole(['super-admin','sub-admin']),async(req,res)=>{
  try {
    const updatemail = await Mail.findOneAndUpdate({Email:req.params.id},{Email:req.body.email},{new:true})
    if(updatemail){
      res.status(200).json({
        message:'Updated'
      })
    }
  } catch (error) {
    res.status(500).json({
      message:error
    })
  }  
})

app.get('/email/:id/delete',authenticateUser,checkUserRole(['super-admin','sub-admin']),async(req,res)=>{
  try {
    const email = await Mail.findOneAndDelete({Email:req.params.id})
    if(email){
      res.status(200).json({
        message:'Deleted'
      })
    }
  } catch (error) {
    res.status(500).json({
      message: error
    })
  }

})

app.put('/user/:id/Approvalstatus',authenticateUser,checkUserRole(['super-admin','sub-admin']),async(req,res)=>{
  try {
    const user = await User.findOne({_id:req.params.id})
    if(user){
      const status = await User.findOneAndUpdate({_id:req.params.id},{isApproved:req.body.status},{new:true})
      if(status){
        res.status(200).json({
          message:`User Verification updated to ${req.body.status}`
        })
      }

    }
    
  } catch (error) {
    res.status(500).json({
      message:error
    })
  }

})

app.get('/user-role',authenticateUser,async(req,res)=>{
  const user = await User.findOne({_id:req.user._id})
  if(user){
    res.status(200).json({
      role:user.role
    })
  }

})

app.put('/user/:id/password/reset',authenticateUser,checkUserRole(['super-admin','sub-admin']),async(req,res)=>{
  const user = await User.findOne({_id:req.params.id})
  if(user){
    const rypto = await crypto.randomBytes(8).toString('hex')
    console.log(rypto)
    const hashedPassword = await bcrypt.hash(rypto,10)
    const reset = await User.findOneAndUpdate({_id:req.params.id},{password:hashedPassword},{new:true})
    if(!reset){
      res.status(201).json({
        message:'Reset Failed'
      })
    }
    //TODO:MAIL TO USER WITH NEW PASSWORD IF ADMIN REQUEST SEND === TRUE
    res.status(200).json({
      message:'Reset Successful'
    })
  }

})

app.put('/user/:id/role/update',authenticateUser,checkUserRole(['super-admin','sub-admin']),async(req,res)=>{
  const user = await User.findOne({_id:req.params.id})
  if(user){
    const roleupgrade = await User.findOneAndUpdate({_id:req.params.id},{role:req.body.role},{new:true})
    if(roleupgrade){
      //TODO:Mail to user about role upgrade
      res.status(200).json({
        message:'Role Uplinked'
      })
    }else{
      res.status(400).json({
        message:'Role Uplinked Failed'
      })
    }
  }
})

app.put('/bill/:id/status/update',authenticateUser,checkUserRole(['super-admin','sub-admin']),async(req,res)=>{
  const bill = await billSchema.findOne({_id:req.params.id})
  if(bill){
    const billupdate = await billSchema.findOneAndUpdate({_id:req.params.id},{status:req.body.status},{new:true})
    if(billupdate){
      //TODO:MAIL STATUS TO BILL AUTHOR
      res.status(200).json({
        message:'Bill status updated'
      })
    }else{
      res.status(400).json({
        message:'Bill status update failed'
      })
    }
  }
})

app.put('/admin/update/password',authenticateUser,checkUserRole(['super-admin','sub-admin']),async (req,res)=>{
  const hash = await bcrypt.hash(req.body.password,10)
  const user = await User.findOneAndUpdate({_id:req.user._id},{password:hash},{new:true})
  if(user){
    res.status(200).json({
      message:'Password Changed'
    })
  }else{
    res.status(400).json({
      message:'Password Change Failed'
    })
  }

})

app.post('/forget',async(req,res)=>{
  const user = await User.findOne({username:req.body.username})
  if(user.isVerified !== true && user.isApproved !== true){
    res.status(200).json({
      message:'Account has not been verified'
    })
  }
  const datatoattach = {
    _id:user._id,
    username:user.username
  }
  const resettoken = await jwt.sign(datatoattach,'secretKey',{ expiresIn: 60 * 5 });
  await User.findOneAndUpdate({_id:user._id},{restToken:resettoken},{new:true})
  const url = `http://localhost:3000/forget/password?token=${resettoken}`
  const data = {
    from:'koby.davis@ethereal.email',
    to:user.username,
    subject:'Reset Password',
    text:`Reset Your Password. ${url}`
  }
  const mailer = await mail(data)
  console.log(mailer)
  res.status(200).json({
    message:'Reset Link has been sent to your mail'
  })
  //TODO:MAIL PASSWORD RESET URL TO USER FOR VERFICATION 
  //TODO:WE NEED TO ADD COLUMN TOKEN TO USER SCHEMA

})
//TODO:TEST THIS API
app.post('/forget/password/reset',authenticateUser,async(req,res)=>{
  if(req.user._id){
   try {
    console.log(req.user._id)
    const hash = await bcrypt.hash(req.body.password,10)
    //add to also find based on resttoken
    const user = await User.findOneAndUpdate({_id:req.user._id,restToken:req.body.token},{password:hash,restToken:null},{new:true})
    //console.log(user)
    res.status(200).json({
      message:'Password Reset Successfully'
    })
   } catch (error) {
    res.status(500).json({
      message:error
    })
   }
  }

})
//user update themselves
app.put('/password/update/',authenticateUser,async(req,res)=>{
  const hash = await bcrypt.hash(req.body.password,10)
  const user = await User.findOneAndUpdate({_id:req.user._id},{password:hash},{new:true})
  if(user){
    res.status(200).json({
      message:'Password Changed'
    })
  }else{
    res.status(400).json({
      message:'Password Change Failed'
    })
  }

})

app.post('/mail',authenticateUser,checkUserRole(['super-admin','sub-admin']),async(req,res)=>{
//TODO:MAIL
})

// User Registration
app.post('/register', [
  check('username').isLength({ min: 5 }),
  check('password').isLength({ min: 8 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password} = req.body;
  const matchmail = await emailmatch(username)
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword,isApproved:matchmail,Regwf:{RegisterComplete:true}});

  try {
    await user.save();
    const token = jwt.sign({ _id: user._id }, 'secretKey',{ expiresIn: 60 * 5 });
    //res.status(201).json({ message: 'User registered successfully' });
    res.header('Authorization', token).json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Registration failed' });
  }
});
const imgstorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0'); // Month is zero-based

    const uploadPath = `./uploads/images/${year}/${month}`;

    // Create the directories if they don't exist
    fs.mkdirSync(uploadPath, { recursive: true });

    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  },
});

  
const uploadimage = multer({ storage: imgstorage });

app.post('/create/profile',authenticateUser, uploadimage.single('Image'),async (req,res)=>{
  if (!req.file) {
    return res.status(400).json({ message: 'No Image uploaded' });
  }

  const imgFilePath = req.file.path;
  try {
    const { fullname, state, Constituency, phone, positionsheld } = req.body
    const newprofile = new Profile({
      fullname:fullname,
      State:state,
      Constituency:Constituency,
      phone:phone,
      profilepicture:imgFilePath,
      positionsheld:positionsheld || null
    })
    await newprofile.save()
    const otp = await otpgen()
    //console.log(otp)
    const update = await User.findOneAndUpdate({_id:req.user._id},{
      $set: {
        profile: newprofile._id,
        otp: otp.secret.base32,
        'Regwf.ProfileComplete': true,
      },
    },{new:true})
    // TODO: MAIL OTP TO USER MAIL ADDRESS
    const data={
      from: 'koby.davis@ethereal.email',
      to: update.username,
      subject: 'Verify Your Account',
      text: `Congratulation On your Registration . Proceed to Verify your account using the 6 Digit OTP below ${otp.token}.`
    }
    const mailer = await mail(data)
    //console.log(mailer)
    res.status(200).json({
      message:'Profile Created.'
    })
  } catch (error) {
   res.status(500).json({
    message: error.message
   })
  }
})

app.post('/user/verify',authenticateUser,async (req,res)=>{
    const user = req.user._id;
    const { otp } = req.body
    try {
      const verifieduser = await User.findOne({_id:user})
        if(verifieduser){
          const verify = await verifyotp(verifieduser.otp,otp)
          if(verify === true){
            const updateuser = await User.findOneAndUpdate({_id:user},{
              $set: {
                otp: null,
                isVerified: true,
                'Regwf.VerifiedComplete': true,
              },
            },{new:true})
            const data={
              from: 'koby.davis@ethereal.email',
              to: updateuser.username,
              subject: 'Verify Your Account',
              text: `Congratulation On Registration and Successful Verification .`
            }
            const mailer = await mail(data)
          res.status(200).json({
            message:'Verified'
          })
          }else{
            res.status(200).json({
              message:'Invalid OTP'
            })
          }
          
        }
      
    } catch (error) {
      res.status(500).json({
        message:error
      })
    }
})

// User Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
  
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
  
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
    if(user.isVerified === true && user.isApproved === true){
    const token = jwt.sign({ _id: user._id,email:user.username }, 'secretKey',);
    res.header('Authorization', token).json({ token });
    }else{
      res.status(201).json({
        message:'Account Approval Pending. Access Denied '
      })
    }
  });

app.get('/user',authenticateUser,async(req,res)=>{
  const user_id = req.user._id;
  console.log(user_id)
  const user = await User.findOne({_id:user_id}).select('-password').populate("profile").exec()
  res.status(200).json({
    user:user
  })


})

// Notify Admin and Create a Report
async function notifyAndCreateReport(newBill, matchingBills) {
    // Send a notification to the admin (you can use email or other means)
    const adminEmail = 'admin@example.com'; // Replace with the admin's email
    const subject = 'Plagiarism Detected';
    const message = `Potential plagiarism detected in document: ${newBill.title}.`;
    // Implement the notification method (e.g., sending an email to the admin)
    //mail function
    try {
      const report = new plagiarismReport({
        newdocument_id:newBill._id,
        newDocumentTitle: newBill.title,
        similarDocuments:matchingBills,
      })
      await report.save()
    } catch (error) {
      console.log(error)
    }
  }

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0'); // Month is zero-based

    const uploadPath = `./uploads/documents/${year}/${month}`;

    // Create the directories if they don't exist
    fs.mkdirSync(uploadPath, { recursive: true });

    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  },
});

  
const upload = multer({ storage: storage });


function calculateCombinedSimilarity(text1, text2) {
  const terms1 = text1.split(' '); // Split by spaces for demonstration (adjust as needed)
  const terms2 = text2.split(' ');

  const filteredTerms1 = stopword.removeStopwords(terms1);
  const filteredTerms2 = stopword.removeStopwords(terms2);

  const intersection = new Set([...filteredTerms1].filter(term => filteredTerms2.includes(term)));

  const union = new Set([...filteredTerms1, ...filteredTerms2]);

  const jaccardSimilarity = intersection.size / union.size;

  const stringSimilarityScore = stringSimilarity.compareTwoStrings(text1, text2);

  return {
    jaccardSimilarity: jaccardSimilarity,
    stringSimilarity: stringSimilarityScore,
  };
}

async function caller (bill,content,historicalTextContents){
  const list = [];
  for (const historicalDoc of historicalTextContents) {
    try {
    const similarityScore = calculateCombinedSimilarity(content, historicalDoc.content);
    const plagiarismThreshold = 0.8; // Adjust as needed
    if (similarityScore.jaccardSimilarity >= plagiarismThreshold) {
      const titlesimilarity = await calculateCombinedSimilarity(bill.title, historicalDoc.title);
      if(titlesimilarity.stringSimilarity < 1){
        list.push({
          documentId: historicalDoc.id,
          title: historicalDoc.title,
          cosineSimilarity:similarityScore.stringSimilarity,
          jaccardSimilarity:similarityScore.jaccardSimilarity
          
        });
      }
      }
    } catch (error) {
     console.log(error)  
    }
  }
  if(list.length > 0){
    await notifyAndCreateReport(bill,list)
  }
    
}
  
app.post('/submit-bill', authenticateUser, upload.single('billPDF'), async (req, res) => {
    const { title, type } = req.body;
    const author = req.user._id;
  
    if (!req.file) {
      return res.status(400).json({ message: 'No PDF file uploaded' });
    }
  
    const pdfFilePath = req.file.path;
    
    try {
      const content = await extractTextFromPDF(pdfFilePath);
    const submissionDate = new Date();
    const year = submissionDate.getFullYear();
    const month = submissionDate.getMonth() + 1;
      const bill = new billSchema({
        title,
        type,
        author,
        pdfFilePath,
        submissionDate,
        month,
        year
      });
  
      await bill.save();
      //mail to sender acknowledging 
   
      const historicalDocuments = await billSchema.find({ _id: { $ne: bill._id } }); // Exclude the newly uploaded document
      const historicalTextContents = [];
      if(historicalDocuments.length > 0){
        for (const historicalDocument of historicalDocuments) {
          const historicalPDFFilePath = historicalDocument.pdfFilePath; // Assuming you store PDF file paths in your Document model
          const historicalTextContent = await extractTextFromPDF(historicalPDFFilePath);
          
          historicalTextContents.push({content:historicalTextContent,id:historicalDocument._id,title:historicalDocument.title});
        }
        await caller(bill,content,historicalTextContents);
      }
      res.status(201).json({ message: 'Bill submitted successfully' });
    } catch (error) {
      res.status(500).json({ message: 'Bill submission failed' });
    }
  });
//create user with 
const createAdminuser = async ()=>{
  const username = 'user2023'
  const password = '12345678'
  const fullname = null
  const state = null
  const phone = null
  const Constituency = null
  const imgFilePath = null
  const checkuser = await User.findOne({role:'super-admin'})
  if(!checkuser){
    const hashedPassword = await bcrypt.hash(password, 10);
  const profile = new Profile({
    fullname:fullname,
    State:state,
    Constituency:Constituency,
    phone:phone,
    profilepicture:imgFilePath,
    positionsheld: null
  })
  await profile.save()
  const user = new User({ username, password: hashedPassword,role:'super-admin',isApproved:true,isVerified:true,profile:profile._id});
  await user.save()
  }
}
app.listen(port, async() => {
  console.log(`Server is running on port ${port}`);
  db()
  createAdminuser()
});
// TODO:ADMIN LOGIN 