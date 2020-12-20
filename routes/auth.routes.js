const {Router} = require('express')
const bcrypt = require('bcryptjs')
const config = require('config')
const {check, validationResult} = require('express-validator')
const jwt = require('jsonwebtoken')
const User = require('../models/User')
const router = Router()

router.post(
    '/register',
    [
        check('email', 'Ýour email is not correctly').isEmail(),
        check('password', 'Min lenght 6 symbols').isLength({min: 6})
    ],
    async (req, res) => {
    try{
        const errors = validationResult(req)

        if(!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Date for registration is not correctly'
            })
        }

        const{name, surname, number, email, login, password} = req.body

        const candidate = await User.findOne({ email })

        if (candidate) {
            return res.status(400).json({ message: 'It`s user has in DB'})
        }

        const hashedPassword = await bcrypt.hash(password, 12)
        const user = new User({name, surname, number, email, password: hashedPassword})
        await user.save()
        res.status(201).json({ message: 'User created'})

    } catch (e) {
        res.status(500).json({message: 'Что-то пошло не так, попробуйте снова'})
    }
})

router.post(
    '/login', 
    [
        check('email', 'Input your email').normalizeEmail().isEmail(),
        check('password', 'Input password').exists()
    ],
    async (req, res) => {
        try{
            const errors = validationResult(req)
    
            if(!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: 'Date for sign in is not correctly'
                })
            }
            
            const {email, password} = req.body

            const user = await User.findOne({ email })

            if(!user) {
                return res.status(400).json({ message: 'User don`t...'})
            }

            const isMatch = await bcrypt.compare(password, user.password)
            
            if (!isMatch) {
                return res.status(400).json({ message: 'Your password isn`t correctly'})
            }

            const token = jwt.sign(
                { userId: user.id},
                config.get('jwtSecret'),
                { expiresIn: '1h'}
            )

            res.json({ token, userId: user.id })
            
        } catch (e) {
            res.status(500).json({message: 'Что-то пошло не так, попробуйте снова'})
        }
})

module.exports = router