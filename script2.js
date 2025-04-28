const express = require("express");
const app = express();
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");

// parse application/json, för att hantera att man POSTar med JSON
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt"); // installeras med npm install bcrypt

// Anropas med GET /gen-hash?password=kalleanka
// Inställningar av servern.
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

async function getDBConnnection() {
  // Här skapas ett databaskopplings-objekt med inställningar för att ansluta till servern och databasen.
  return await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "anvandare",
  });
}

//Gör något bra med decoded.

app.get("/", (req, res) => {
  res.send(`<h1>Doumentation EXEMPEL</h1>
  <ul><li> GET /users</li><li>GET /name</li><li>GET /food/:foodType</li><li>GET /users/:username</li><li>POST /login - tar in JSON på formatet {"username":"", "password":""</li></ul>`);
});

function checkToken(req, res) {
  let authHeader = req.headers["authorization"];
  if (authHeader === undefined) {
  }
  let token = authHeader.slice(7);
  let decoded;
  try {
    decoded = jwt.verify(token, "ketchup");
    return decoded;
  } catch (err) {
    console.log(err);
    res.status(401).send("Invalid auth token");
  }
}

app.get("/users", async (req, res) => {
  let connection = await getDBConnnection();
  let sql = "SELECT * FROM users";

  decoded = checkToken(req, res);
  if (decoded) {
    if (req.query.username) {
      sql = `SELECT * FROM users WHERE username = ?`;
    }
    let [results] = await connection.execute(sql);
    res.json(results[0]);
  }
});

app.get("/users/:username", async (req, res) => {
  decoded = checkToken(req, res);
  if (decoded) {
    let connection = await getDBConnnection();
    let sql = `SELECT * FROM users WHERE username = ?`;
    let [results] = await connection.execute(sql, [req.params.username]);
    res.json(results);
  }
});

app.get("/name", (req, res) => {
  res.send(req.query);
});

app.get("/food/:foodType", (req, res) => {
  res.send(req.params);
});

app.post("/users", async function (req, res) {
  decoded = checkToken(req, res);
  if (decoded) {
    if (
      req.body &&
      typeof req.body.username == "string" &&
      req.body.name &&
      req.body.password
    ) {
      let user = req.body;
      let connection = await getDBConnnection();
      let sql = `INSERT INTO users (username, name, password) VALUES (?,?,?)`;

      const salt = await bcrypt.genSalt(10); // genererar ett salt till hashning
      const hashedPassword = await bcrypt.hash(req.body.password, salt); //hashar lösenordet

      let [results] = await connection.execute(sql, [
        req.body.username,
        req.body.name,
        hashedPassword,
      ]);
      user.password = hashedPassword;
      user.id = results.insertId;
      res.json(user);
    } else {
      res.sendStatus(422);
    }
  }
});

app.put("/users/:id", async (req, res) => {
  decoded = checkToken(req, res);
  if (decoded) {
    let connection = await getDBConnnection();
    if (connection) {
      let sql = `UPDATE users SET name =?, password=? WHERE id=?`;

      const salt = await bcrypt.genSalt(10); // genererar ett salt till hashning
      const hashedPassword = await bcrypt.hash(req.body.password, salt); //hashar lösenordet

      let [results] = await connection.execute(sql, [
        req.body.name,
        hashedPassword,
        req.params.id,
      ]);
      if (results.affectedRows > 0) {
        res.status(200).json(results);
      } else {
        res.status(400).send("Det finns ingenting att hämta");
      }
    } else {
      res.sendStatus(500);
    }
  }
});
app.post("/login", async (req, res) => {
  let connection = await getDBConnnection();
  let sql = `SELECT * FROM users WHERE username = ?`;
  let [results] = await connection.execute(sql, [req.body.username]);
  if (results.length > 0) {
    const user = results[0];
    const isPasswordValid = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (isPasswordValid) {
      let payload = {
        sub: user.id,
        name: user.name,
        exp: Date.now() / 1000 + 60 * 120,
      };
      let token = jwt.sign(payload, "ketchup");
      res.json(token);
    } else {
      res.status(400).send("Felaktigt användarnamn eller lösenord");
    }
  } else {
    res.status(400).send("Felaktigt användarnamn eller lösenord");
  }
});
const port = 3000;
app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
