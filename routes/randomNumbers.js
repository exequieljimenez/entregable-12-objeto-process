

export function numerosRandom(x = 100000000){const numeros = {}
for(let i = 0; i < x; i++) {
    const randomNum = Math.ceil(Math.random() * 1000)
    numeros[randomNum] ? numeros[randomNum]++ : numeros[randomNum] = 1
}
return numeros
}

process.on('message', valor => {
    let calcular
    if(valor === null) {
        calcular = numerosRandom()
    } else {
        calcular = numerosRandom(valor)
    }
    process.send(`Calculo de numeros random ${JSON.stringify(calcular)}`)
})