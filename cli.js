import inquirer from 'inquirer';
import qrcodeTerminal from 'qrcode-terminal';
import { authenticator } from 'otplib';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
process.loadEnvFile();

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    secret: String,
    twoFAEnabled: { type: Boolean, default: false },
});

userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

const User = mongoose.model('User', userSchema);

const createUser = async (username, password) => {
    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            console.log('User already exists');
            return;
        }

        const user = new User({ username, password });
        await user.save();
        console.log('User registered successfully');
    } catch (error) {
        console.error('Error registering user', error);
    }
};

const setup2FA = async (username) => {
    try {
        const user = await User.findOne({ username });
        if (!user) {
            console.log('User not found');
            return;
        }

        const secret = authenticator.generateSecret();
        user.secret = secret;
        user.twoFAEnabled = false;
        await user.save();

        console.log('Secret generated:', secret);
        qrcodeTerminal.generate(authenticator.keyuri(username, 'Blacklist', secret), { small: true });
        console.log('QR Code generated for 2FA setup');
    } catch (error) {
        console.error('Error setting up 2FA', error);
    }
};

const runCLI = async () => {
    const answers = await inquirer.prompt([
        {
            type: 'list',
            name: 'action',
            message: 'What would you like to do?',
            choices: ['Register a new user', 'Set up 2FA for a user', 'Exit'],
        },
    ]);

    if (answers.action === 'Register a new user') {
        const userAnswers = await inquirer.prompt([
            {
                type: 'input',
                name: 'username',
                message: 'Enter username:',
                validate: (value) => value.trim() !== '' || 'Username is required',
            },
            {
                type: 'password',
                name: 'password',
                message: 'Enter password:',
                mask: '*',
                validate: (value) => value.trim() !== '' || 'Password is required',
            },
        ]);

        await createUser(userAnswers.username, userAnswers.password);
    } else if (answers.action === 'Set up 2FA for a user') {
        const userAnswers = await inquirer.prompt([
            {
                type: 'input',
                name: 'username',
                message: 'Enter username:',
                validate: (value) => value.trim() !== '' || 'Username is required',
            },
        ]);

        await setup2FA(userAnswers.username);
    }

    if (answers.action !== 'Exit') {
        runCLI();
    } else {
        mongoose.disconnect();
        process.exit(0);
    }
};

runCLI();