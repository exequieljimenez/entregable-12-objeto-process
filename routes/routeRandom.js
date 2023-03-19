import express, { query } from 'express';
const {Router} = express
import {fork} from 'child_process';

const randomRouter = new Router()
const forkedProcess = fork('./routes/randomNumbers.js')

randomRouter.use(express.json())
randomRouter.use(express.urlencoded({extended: true}))

randomRouter.get('/random', (req, res) => {
    let numero = req.query
    forkedProcess.send(parseInt(numero.valor));
    forkedProcess.on('message', stringified => {
        console.log(stringified)
    });
    res.send('Calculando numeros random en forked process')
    
})

export default randomRouter