require("dotenv").config();

const express = require("express");
const session = require("express-session");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const path = require("path");

const app = express();

const PORT = 3000;


/* BANCO */

const banco = mysql.createPool({

    host: process.env.DB_HOST,

    port: process.env.DB_PORT || 3306,

    user: process.env.DB_USER,

    password: process.env.DB_PASSWORD,

    database: process.env.DB_NAME,

    connectionLimit: 10
});


/* CONFIGURAÇÕES */

app.use(express.json());

app.use(
    express.urlencoded({
        extended: true
    })
);


app.use(
    session({

        secret:
            process.env.SESSION_SECRET ||
            "chave-autofix",

        resave: false,

        saveUninitialized: false,

        cookie: {

            maxAge:
                30 * 60 * 1000,

            httpOnly: true,

            sameSite: "lax"
        }

    })
);


app.use(
    express.static(
        path.join(
            __dirname,
            "public"
        )
    )
);


/* =========================
   CPF
========================= */

function limparCPF(cpf) {

    return String(cpf)
        .replace(/\D/g, "");
}


function hashCPF(cpf) {

    return crypto
        .createHash("sha256")
        .update(cpf)
        .digest("hex");
}


function chaveCPF() {

    return Buffer.from(
        process.env.CPF_ENCRYPTION_KEY,
        "hex"
    );
}


function criptografarCPF(cpf) {

    const iv =
        crypto.randomBytes(12);

    const cipher =
        crypto.createCipheriv(
            "aes-256-gcm",
            chaveCPF(),
            iv
        );

    const dados =
        Buffer.concat([
            cipher.update(
                cpf,
                "utf8"
            ),
            cipher.final()
        ]);

    const tag =
        cipher.getAuthTag();

    return [

        iv.toString("base64"),

        tag.toString("base64"),

        dados.toString("base64")

    ].join(".");
}


function descriptografarCPF(valor) {

    const partes =
        valor.split(".");


    const decipher =
        crypto.createDecipheriv(
            "aes-256-gcm",
            chaveCPF(),
            Buffer.from(
                partes[0],
                "base64"
            )
        );


    decipher.setAuthTag(
        Buffer.from(
            partes[1],
            "base64"
        )
    );


    return Buffer.concat([

        decipher.update(
            Buffer.from(
                partes[2],
                "base64"
            )
        ),

        decipher.final()

    ]).toString("utf8");
}


/* =========================
   LOGIN
========================= */

function verificarLogin(
    req,
    res,
    next
) {

    if (!req.session.usuario) {

        return res.status(401).json({

            erro:
                "Sessão expirada."

        });
    }

    next();
}


app.post(
    "/api/login",
    async (req, res) => {

        try {

            const {
                usuario,
                senha
            } = req.body;


            const [usuarios] =
                await banco.query(

                    `SELECT *
                     FROM usuarios
                     WHERE usuario = ?
                     LIMIT 1`,

                    [usuario]
                );


            if (
                usuarios.length === 0
            ) {

                return res
                    .status(401)
                    .json({

                        erro:
                            "Usuário ou senha incorretos."

                    });
            }


            const valido =
                await bcrypt.compare(

                    senha,

                    usuarios[0]
                        .senha_hash
                );


            if (!valido) {

                return res
                    .status(401)
                    .json({

                        erro:
                            "Usuário ou senha incorretos."

                    });
            }


            req.session.usuario = {

                id:
                    usuarios[0].id,

                nome:
                    usuarios[0].nome

            };


            res.json({

                nome:
                    usuarios[0].nome

            });


        } catch (erro) {

            console.log(erro);

            res.status(500).json({

                erro:
                    "Erro no login."

            });
        }
    }
);


/* LOGOUT */

app.post(
    "/api/logout",
    (req, res) => {

        req.session.destroy(
            function() {

                res.json({
                    ok: true
                });

            }
        );
    }
);


/* USUÁRIO */

app.get(
    "/api/me",
    verificarLogin,
    (req, res) => {

        res.json(
            req.session.usuario
        );

    }
);


/* =========================
   CLIENTES
========================= */

app.get(
    "/api/clientes",
    verificarLogin,
    async (req, res) => {

        try {

            const busca =
                req.query.busca || "";


            let sql =
                `SELECT *
                 FROM clientes`;

            let parametros = [];


            if (busca) {

                sql +=
                    ` WHERE nome LIKE ?
                      OR cpf_hash = ?`;

                parametros.push(
                    "%" + busca + "%"
                );

                parametros.push(
                    hashCPF(
                        limparCPF(busca)
                    )
                );
            }


            sql +=
                " ORDER BY nome";


            const [clientes] =
                await banco.query(
                    sql,
                    parametros
                );


            const resultado =
                clientes.map(
                    function(cliente) {

                        return {

                            id:
                                cliente.id,

                            nome:
                                cliente.nome,

                            cpf:
                                descriptografarCPF(
                                    cliente
                                        .cpf_criptografado
                                ),

                            telefone:
                                cliente.telefone,

                            email:
                                cliente.email

                        };

                    }
                );


            res.json(resultado);


        } catch (erro) {

            res.status(500).json({

                erro:
                    "Erro ao buscar clientes."

            });
        }
    }
);


/* CADASTRAR CLIENTE */

app.post(
    "/api/clientes",
    verificarLogin,
    async (req, res) => {

        try {

            const {
                nome,
                cpf,
                telefone,
                email
            } = req.body;


            const cpfLimpo =
                limparCPF(cpf);


            if (
                !nome ||
                cpfLimpo.length !== 11
            ) {

                return res
                    .status(400)
                    .json({

                        erro:
                            "Nome e CPF válido são obrigatórios."

                    });
            }


            await banco.query(

                `INSERT INTO clientes
                (
                    nome,
                    cpf_criptografado,
                    cpf_hash,
                    telefone,
                    email
                )
                VALUES (?, ?, ?, ?, ?)`,

                [

                    nome,

                    criptografarCPF(
                        cpfLimpo
                    ),

                    hashCPF(
                        cpfLimpo
                    ),

                    telefone || "",

                    email || ""

                ]
            );


            res.json({
                ok: true
            });


        } catch (erro) {

            res.status(500).json({

                erro:
                    "Erro ao cadastrar cliente."

            });
        }
    }
);


/* EXCLUIR CLIENTE */

app.delete(
    "/api/clientes/:id",
    verificarLogin,
    async (req, res) => {

        try {

            await banco.query(

                `DELETE FROM clientes
                 WHERE id = ?`,

                [req.params.id]
            );


            res.json({
                ok: true
            });


        } catch (erro) {

            res.status(400).json({

                erro:
                    "Não é possível excluir este cliente pois existem registros vinculados."

            });
        }
    }
);


/* =========================
   VEÍCULOS
========================= */

app.get(
    "/api/veiculos",
    verificarLogin,
    async (req, res) => {

        try {

            const [veiculos] =
                await banco.query(

                    `SELECT
                        v.*,
                        c.nome AS cliente
                     FROM veiculos v
                     INNER JOIN clientes c
                     ON c.id = v.cliente_id
                     ORDER BY v.placa`

                );


            res.json(veiculos);


        } catch (erro) {

            res.status(500).json({

                erro:
                    "Erro ao buscar veículos."

            });
        }
    }
);


app.post(
    "/api/veiculos",
    verificarLogin,
    async (req, res) => {

        try {

            const {
                placa,
                marca,
                modelo,
                ano,
                cliente_id
            } = req.body;


            if (!cliente_id) {

                return res
                    .status(400)
                    .json({

                        erro:
                            "Selecione um cliente."

                    });
            }


            await banco.query(

                `INSERT INTO veiculos
                (
                    placa,
                    marca,
                    modelo,
                    ano,
                    cliente_id
                )
                VALUES (?, ?, ?, ?, ?)`,

                [
                    placa,
                    marca,
                    modelo,
                    ano,
                    cliente_id
                ]
            );


            res.json({
                ok: true
            });


        } catch (erro) {

            res.status(500).json({

                erro:
                    "Erro ao cadastrar veículo."

            });
        }
    }
);


app.delete(
    "/api/veiculos/:id",
    verificarLogin,
    async (req, res) => {

        try {

            await banco.query(

                `DELETE FROM veiculos
                 WHERE id = ?`,

                [req.params.id]
            );


            res.json({
                ok: true
            });


        } catch (erro) {

            res.status(400).json({

                erro:
                    "Não é possível excluir este veículo pois ele possui uma ordem de serviço."

            });
        }
    }
);


/* =========================
   ORDENS
========================= */

app.get(
    "/api/os",
    verificarLogin,
    async (req, res) => {

        try {

            const [ordens] =
                await banco.query(

                    `SELECT
                        os.*,
                        c.nome AS cliente,
                        v.placa,
                        v.marca,
                        v.modelo
                     FROM ordens_servico os
                     INNER JOIN clientes c
                     ON c.id = os.cliente_id
                     INNER JOIN veiculos v
                     ON v.id = os.veiculo_id
                     ORDER BY
                        os.data_abertura DESC`

                );


            res.json(ordens);


        } catch (erro) {

            res.status(500).json({

                erro:
                    "Erro ao buscar ordens."

            });
        }
    }
);


app.post(
    "/api/os",
    verificarLogin,
    async (req, res) => {

        try {

            const {
                cliente_id,
                veiculo_id,
                servico,
                valor,
                data_abertura,
                status
            } = req.body;


            await banco.query(

                `INSERT INTO ordens_servico
                (
                    cliente_id,
                    veiculo_id,
                    servico,
                    valor,
                    data_abertura,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?)`,

                [

                    cliente_id,

                    veiculo_id,

                    servico,

                    valor,

                    data_abertura,

                    status

                ]
            );


            res.json({
                ok: true
            });


        } catch (erro) {

            res.status(500).json({

                erro:
                    "Erro ao cadastrar ordem."

            });
        }
    }
);


app.delete(
    "/api/os/:id",
    verificarLogin,
    async (req, res) => {

        try {

            await banco.query(

                `DELETE FROM ordens_servico
                 WHERE id = ?`,

                [req.params.id]
            );


            res.json({
                ok: true
            });


        } catch (erro) {

            res.status(500).json({

                erro:
                    "Erro ao excluir ordem."

            });
        }
    }
);


/* =========================
   SERVIDOR
========================= */

app.listen(
    PORT,
    function() {

        console.log(
            "AutoFix rodando em http://localhost:" +
            PORT
        );

    }
);

