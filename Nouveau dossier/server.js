const express = require("express");
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const multer = require('multer');
const storage = multer.memoryStorage();
const upload = multer({ storage: multer.memoryStorage() });
const app = express();
const port = 3000;
const path = require('path');
var mysql = require('mysql');
var connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'platforme_redaction'
});

connection.connect();
app.use(bodyParser.json());


app.get("/addclient", function (req, res) {
    const { nom, prenom, age, CIN, adresse, email, password } = req.body;
    // Vérifiez d'abord si l'email existe déjà
    const checkEmailQuery = 'SELECT email FROM client WHERE email = ?';
    connection.query(checkEmailQuery, [email], async (err, results) => {
        if (err) throw err;
        // Si l'email existe déjà, renvoyez un message d'erreur
        if (results.length > 0) {
            return res.send('Cet email est déjà utilisé. Veuillez en choisir un autre.');
        }
        // Vérifiez si le mot de passe contient une lettre majuscule et une lettre spéciale
        const uppercaseRegex = /[A-Z]/;
        const specialCharRegex = /[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]/;
        const numberRegex = /[1-9]/;

        if (!uppercaseRegex.test(password) || !specialCharRegex.test(password) || !numberRegex.test(password) || password.length < 8) {
            return res.send('Le mot de passe doit contenir au moins une lettre majuscule et une lettre spéciale et de taille 8 caracteres au minimum.');
        }
        // Cryptage du mot de passe
        const hashedPassword = await bcrypt.hash(password, 10);
        // Si l'email n'existe pas et le mot de passe est conforme, insérez les données dans la base de données
        const sql = "INSERT INTO client (nom,prenom,age,CIN,adresse,email,password) VALUES (?,?,?,?,?,?,?)";
        connection.query(sql, [nom, prenom, age, CIN, adresse, email, hashedPassword], (err, result) => {
            if (err) throw err;
            console.log('Utilisateur inscrit avec l\'ID : ' + result.insertId);
            res.send('Inscription réussie !');
        });
    })
});




// Endpoint pour gérer les données du formulaire
app.post('/addredacteur', upload.single('cv'), (req, res) => {
    const { nom, prenom, age, cin, adresse, email, password, profession, numcompte } = req.body;
    // Vérifiez d'abord si l'email existe déjà
    const checkEmailQuery = 'SELECT email FROM redacteur WHERE email = ?';
    connection.query(checkEmailQuery, [email], async (err, results) => {
        if (err) throw err;
        // Si l'email existe déjà, renvoyez un message d'erreur
        if (results.length > 0) {
            return res.send('Cet email est déjà utilisé. Veuillez en choisir un autre.');
        }
        // Vérifiez si le mot de passe contient une lettre majuscule et une lettre spéciale
        const uppercaseRegex = /[A-Z]/;
        const specialCharRegex = /[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]/;
        const numberRegex = /[1-9]/;

        if (!uppercaseRegex.test(password) || !specialCharRegex.test(password) || !numberRegex.test(password) || password.length < 8) {
            return res.send('Le mot de passe doit contenir au moins une lettre majuscule et une lettre spéciale et de taille 8 caracteres au minimum.');
        }
        // Cryptage du mot de passe
        const hashedPassword = await bcrypt.hash(password, 10);

        // Accéder au fichier téléversé (si présent)
        const cvFileBuffer = req.file ? req.file.buffer : null;

        // Insérer vos données dans la base de données
        const insertQuery = 'INSERT INTO redacteur (nom, prenom, age, cin, adresse, email, password, profession, numcompte, cv) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
        connection.query(insertQuery, [nom, prenom, age, cin, adresse, email, hashedPassword, profession, numcompte, cvFileBuffer], (error, results, fields) => {
            if (error) {
                console.error('Erreur lors de linsertion des données :', error);
                res.status(500).send('Erreur lors de linsertion des données dans la base de données.');
            } else {
                console.log('Données insérées avec succès dans la base de données.');
                res.send('Données insérées avec succès dans la base de données.');
            }
        });
    })
});

// Variable de l'application pour stocker l'ID du client temporairement
let userIdForProject;
app.post("/login", function (req, res) {
    const email = req.body.email;
    const enteredPassword = req.body.password;
    const checkClientQuery = 'SELECT IDC as userId, email, password FROM client WHERE email = ?';
    const checkRedacteurQuery = 'SELECT IDR as userId, email, password FROM redacteur WHERE email = ?';
    // Utilisation de la promesse pour gérer l'asynchronicité
    const loginPromise = new Promise((resolve, reject) => {
        // Vérification dans la table client
        connection.query(checkClientQuery, [email], async (err, clientResults) => {
            if (err) {
                reject(err);
                return;
            }

            if (clientResults.length > 0) {
                const hashedPasswordFromDatabase = clientResults[0].password;

                bcrypt.compare(enteredPassword, hashedPasswordFromDatabase, (err, passwordMatch) => {
                    if (err) {
                        reject(err);
                        return;
                    }

                    if (passwordMatch) {
                        userIdForProject = clientResults[0].userId;
                        resolve(userIdForProject);
                    } else {
                        reject('Mot de passe incorrect dans la table "client". Veuillez réessayer.');
                    }
                });
            } else {  // Vérification dans la table rédacteur si l'utilisateur n'est pas trouvé dans la table client
                connection.query(checkRedacteurQuery, [email], async (err, redacteurResults) => {
                    if (err) {
                        reject(err);
                        return;
                    }

                    if (redacteurResults.length > 0) {
                        const hashedPasswordFromDatabase = redacteurResults[0].password;

                        bcrypt.compare(enteredPassword, hashedPasswordFromDatabase, (err, passwordMatch) => {
                            if (err) {
                                reject(err);
                                return;
                            }

                            if (passwordMatch) {
                                userIdForProject = redacteurResults[0].userId;
                                resolve(userIdForProject);
                            } else {
                                reject('Mot de passe incorrect dans la table "rédacteur". Veuillez réessayer.');
                            }
                        });
                    } else {
                        reject('Utilisateur non trouvé. Veuillez vous inscrire.');
                    }
                });
            }
        });
    });

    loginPromise
        .then((userId) => {
            res.send(`Authentification réussie avec l'ID ${userId}!`);
        })
        .catch((error) => {
            console.error('Erreur lors de l\'authentification :', error);
            res.status(500).send(`Erreur lors de l'authentification : ${error}`);
        });
});


app.post('/ajoutprojet', upload.single('fichierprojet'), (req, res) => {
    // Utilisez clientIdForProject pour obtenir l'ID du client
    const clientId = userIdForProject;
    // Accéder au fichier projet téléversé (si présent)
    const fichierProjetBuffer = req.file ? req.file.buffer : null;
    // Vérifiez si le client existe (vous pouvez le faire de manière plus approfondie si nécessaire)
    const checkClientQuery = 'SELECT IDC FROM client WHERE IDC = ?';
    connection.query(checkClientQuery, [clientId], async (err, clientResults) => {
        if (err) {
            console.error('Erreur lors de la vérification du client :', err);
            return res.status(500).send('Erreur lors de la vérification du client.');
        }

        if (clientResults.length === 0) {
            return res.send('Client non trouvé. Veuillez vous connecter en tant que client valide.');
        }

        // Insérez vos données dans la table du projet avec l'ID du client
        const { titre, description, prix, delailiv } = req.body;

        const insertQuery = 'INSERT INTO projet (titre, fichierprojet, prix, description,  delailiv, IDC) VALUES (?, ?, ?, ?, ?, ?)';
        connection.query(insertQuery, [titre, fichierProjetBuffer, prix, description, delailiv, clientId], (error, results, fields) => {
            if (error) {
                console.error('Erreur lors de l\'insertion des données du projet :', error);
                res.status(500).send('Erreur lors de l\'insertion des données du projet dans la base de données.');
            } else {
                console.log('Données du projet insérées avec succès dans la base de données.');
                res.send('Données du projet insérées avec succès dans la base de données.');
            }
        });
    });
});

app.put('/updateredacteur', upload.single('cv'), async (req, res) => {
    const redacteurId = userIdForProject;;


    const { nom, prenom, age, cin, adresse, email, password, profession, numcompte } = req.body;

    // Vérifiez d'abord si l'email existe déjà pour un autre redacteur (en excluant l'email du redacteur actuel si l'email change)
    const checkEmailQuery = 'SELECT IDR FROM redacteur WHERE email = ? AND IDR != ?';
    connection.query(checkEmailQuery, [email, redacteurId], async (err, emailResults) => {
        if (err) throw err;

        // Si l'email existe déjà pour un autre redacteur et l'email change, renvoyez un message d'erreur
        if (emailResults.length > 0) {
            if (email !== req.body.oldEmail) {
                return res.send('Cet email est déjà utilisé par un autre redacteur. Veuillez en choisir un autre.');
            }
        }

        // Vérifiez si le mot de passe contient une lettre majuscule, une lettre spéciale et un chiffre
        const uppercaseRegex = /[A-Z]/;
        const specialCharRegex = /[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]/;
        const numberRegex = /[0-9]/;

        if (
            (password && !uppercaseRegex.test(password)) ||
            (password && !specialCharRegex.test(password)) ||
            (password && !numberRegex.test(password)) ||
            (password && password.length < 8)
        ) {
            return res.send(
                'Le mot de passe doit contenir au moins une lettre majuscule, une lettre spéciale et un chiffre, et être d\'une longueur d\'au moins 8 caractères.'
            );
        }
        // Accéder au nouveau fichier téléversé (si présent)
        const nouveauCvFileBuffer = req.file ? req.file.buffer : null;


        // Cryptage du mot de passe si fourni
        const hashedPassword = password ? await bcrypt.hash(password, 10) : null;

        // Mise à jour des données dans la base de données
        const updateQuery =
            'UPDATE redacteur SET nom=?, prenom=?, age=?, cin=?, adresse=?, email=?, password=?, profession=?, numcompte=?, cv=? WHERE IDR=?';

        connection.query(
            updateQuery,
            [nom, prenom, age, cin, adresse, email, hashedPassword, profession, numcompte, nouveauCvFileBuffer, redacteurId],
            (error, results, fields) => {
                if (error) {
                    console.error('Erreur lors de la mise à jour des données :', error);
                    res.status(500).send('Erreur lors de la mise à jour des données dans la base de données.');
                } else {
                    console.log('Données mises à jour avec succès dans la base de données.');
                    res.send('Données mises à jour avec succès dans la base de données.');
                }
            }
        );
        console.log('req.body:', req.body);
    });
});

app.put('/updateclient', async (req, res) => {

    const clientId = userIdForProject;
    const { nom, prenom, age, cin, adresse, email, password } = req.body;

    // Vérifiez d'abord si l'email existe déjà pour un autre client (en excluant l'email du client actuel si l'email change)
    const checkEmailQuery = 'SELECT IDC FROM client WHERE email = ? AND IDC != ?';
    connection.query(checkEmailQuery, [email, clientId], async (err, emailResults) => {
        if (err) throw err;

        // Si l'email existe déjà pour un autre client et l'email change, renvoyez un message d'erreur
        if (emailResults.length > 0) {
            if (email !== req.body.oldEmail) {
                return res.send('Cet email est déjà utilisé par un autre client. Veuillez en choisir un autre.');
            }
        }

        // Vérifiez si le mot de passe contient une lettre majuscule, une lettre spéciale et un chiffre
        const uppercaseRegex = /[A-Z]/;
        const specialCharRegex = /[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]/;
        const numberRegex = /[0-9]/;

        if (
            (password && !uppercaseRegex.test(password)) ||
            (password && !specialCharRegex.test(password)) ||
            (password && !numberRegex.test(password)) ||
            (password && password.length < 8)
        ) {
            return res.send(
                'Le mot de passe doit contenir au moins une lettre majuscule, une lettre spéciale et un chiffre, et être d\'une longueur d\'au moins 8 caractères.'
            );
        }

        // Cryptage du mot de passe si fourni
        const hashedPassword = password ? await bcrypt.hash(password, 10) : null;

        // Mise à jour des données dans la base de données
        const updateQuery =
            'UPDATE client SET nom=?, prenom=?, age=?, cin=?, adresse=?, email=?, password=? WHERE IDC=?';

        connection.query(
            updateQuery,
            [nom, prenom, age, cin, adresse, email, hashedPassword, clientId],
            (error, results, fields) => {
                if (error) {
                    console.error('Erreur lors de la mise à jour des données :', error);
                    res.status(500).send('Erreur lors de la mise à jour des données dans la base de données.');
                } else {
                    console.log('Données mises à jour avec succès dans la base de données.');
                    res.send('Données mises à jour avec succès dans la base de données.');
                }
            }
        );
    });
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});