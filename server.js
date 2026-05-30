'use strict';
require('dotenv').config();

const express    = require('express');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const sqlite3    = require('sqlite3').verbose();
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const path       = require('path');
const fs         = require('fs');

// ═══════════════════════════════════════
//  CONFIG
// ═══════════════════════════════════════
const PORT               = process.env.PORT               || 3000;
const JWT_SECRET         = process.env.JWT_SECRET         || 'dev-secret-change-in-prod-AAAA';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev-refresh-change-in-prod-BBBB';
const GEMINI_API_KEY     = process.env.GEMINI_API_KEY     || '';
const DB_PATH            = process.env.DB_PATH            || path.join(__dirname, 'data', 'bfc.db');

// ═══════════════════════════════════════
//  BASE DE DONNÉES SQLite
// ═══════════════════════════════════════
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new sqlite3.Database(DB_PATH, err => {
  if (err) { console.error('DB error:', err); process.exit(1); }
  console.log('✅ DB connectée:', DB_PATH);
});

// Helpers promisifiés
const dbRun = (sql, p = []) => new Promise((res, rej) =>
  db.run(sql, p, function(err) { err ? rej(err) : res(this); }));
const dbGet = (sql, p = []) => new Promise((res, rej) =>
  db.get(sql, p, (err, row) => err ? rej(err) : res(row)));
const dbAll = (sql, p = []) => new Promise((res, rej) =>
  db.all(sql, p, (err, rows) => err ? rej(err) : res(rows)));

// Init tables
db.serialize(() => {
  db.run('PRAGMA journal_mode = WAL');
  db.run('PRAGMA foreign_keys = ON');
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'obs',
    nom TEXT DEFAULT '',
    email TEXT DEFAULT '',
    actif INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ext_id TEXT UNIQUE NOT NULL,
    arbitre TEXT DEFAULT '',
    arb_email TEXT DEFAULT '',
    obs_nom TEXT DEFAULT '',
    categorie TEXT DEFAULT '',
    competition TEXT DEFAULT '',
    equipes TEXT DEFAULT '',
    date_match TEXT DEFAULT '',
    score TEXT DEFAULT '0-0',
    note_20 REAL DEFAULT 0,
    note_100 INTEGER DEFAULT 0,
    statut TEXT DEFAULT '🟡 En attente de validation',
    data_json TEXT DEFAULT '{}',
    auteur_id INTEGER DEFAULT 0,
    auteur_nom TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS conn_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER DEFAULT 0,
    username TEXT DEFAULT '',
    role TEXT DEFAULT '',
    action TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    timestamp TEXT DEFAULT (datetime('now'))
  )`);

  // Seed comptes par défaut
  db.get('SELECT COUNT(*) as c FROM users', (err, row) => {
    if (!err && row && row.c === 0) {
      const ins = db.prepare('INSERT INTO users (username, password, role, nom) VALUES (?, ?, ?, ?)');
      const defaults = [
        { u: 'obs',   p: '89Sidi-Aich', r: 'obs',   n: 'Observateur' },
        { u: 'gest',  p: '13Sidi-Aich', r: 'gest',  n: 'Gestionnaire CDA' },
        { u: 'admin', p: '75Sidi-Aich', r: 'admin', n: 'Administrateur' }
      ];
      defaults.forEach(d => ins.run(d.u, bcrypt.hashSync(d.p, 12), d.r, d.n));
      ins.finalize();
      console.log('✅ Comptes par défaut créés');
    }
  });
});

  db.run(`CREATE TABLE IF NOT EXISTS arbitres (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT NOT NULL,
    prenom TEXT DEFAULT '',
    licence TEXT DEFAULT '',
    localite TEXT DEFAULT '',
    telephone TEXT DEFAULT '',
    email TEXT DEFAULT '',
    club TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  )`);

  // Seed arbitres
  db.get('SELECT COUNT(*) as c FROM arbitres', (err, row) => {
    if (!err && row && row.c === 0) {
      const ins2 = db.prepare('INSERT INTO arbitres (nom,prenom,licence,localite,telephone,email,club) VALUES (?,?,?,?,?,?,?)');
      const arbs = [
        ['ABOU EL MANADIL','Mehdi','841810300','MONETEAU','07 49 82 14 70','abou-elmanadil.mehdi@lbfc-foot.fr','AUXERRE SC'],
        ['AHOUISSOUSSI','JEAN PAUL','2427605437','AUXERRE','06 29 30 79 41','ahouissoussi.jeanpaul@lbfc-foot.fr','A.J. AUXERRE'],
        ['AICI','SEYLAN','9604117931','','06 60 64 78 00','melka89@hotmail.fr','ENTENTE FLORENTINOISE'],
        ['AISSOUS','MOHAMED','9603258314','','07 83 21 47 33','sarra.aissous@hotmail.fr','AUXERRE SPORTS CITOYEN'],
        ['AKAROUCHE','SOUFIAN','861816850','ST FLORENTIN','07 62 18 62 26','akarouche.soufian@lbfc-foot.fr','ENTENTE FLORENTINOISE F C'],
        ['AKLAND','JAY','2548470184','','07 52 06 37 71','ackland.jay@lbfc-foot.fr','PARON'],
        ['AMARAL','RONAN','2546137182','DIJON','06 19 47 24 58','amaral.ronan@lbfc-foot.fr','E.S. APPOIGNY'],
        ['BABO','DONATIEN','2546402519','MIGENNES','07 69 82 77 97','babo.donatien@lbfc-foot.fr','AM.S.U. CHEMINOTE MIGENNES'],
        ['BAHLOUL','KACIM','9603182438','','06 66 51 40 84','yboussalla@gmail.com','AUXERRE SPORTS CITOYEN'],
        ['BALLU','RUDY','861810589','JOIGNY','06 22 79 28 12','ballu.rudy@lbfc-foot.fr','U.S. DE CERISIERS'],
        ['BASLER','AMANDINE','2546366725','TROYES','06 66 65 92 68','basler.amandine@lbfc-foot.fr','U.S. DE CERISIERS'],
        ['BEN AMAR','LAHOUARI','838412993','ST FLORENTIN','06 20 99 57 75','benamar.lahouari@lbfc-foot.fr','ENTENTE FLORENTINOISE F C'],
        ['BERGERY','Simon','2548347142','','06 26 69 79 99','bergery.simon@lbfc-foot.fr','HÉRY'],
        ['BERTE','MAXIME','871816565','TRIGUERES','06 50 16 62 39','berte.maxime@lbfc-foot.fr','U.S. JOIGNY'],
        ['BIHL','Dorian','9603474980','VALRAVILLON','07 60 57 89 02','bihl.dorian@lbfc-foot.fr','AILLANT SP.'],
        ['BISIAUX','LOUIS','9603545971','AUXERRE','06 74 90 62 20','bisiaux.louis@lbfc-foot.fr','STADE AUXERROIS'],
        ['BIZARION','KEVIN','801817716','','06 23 38 24 21','kevinbizarion@outlook.fr','SEIGNELAY'],
        ['BOYER','FRANCOIS','9604247743','','06 77 06 91 29','boyer.francois@lbfc-foot.fr','AM.S.U. CHEMINOTE DE MIGENNES'],
        ['BRAGE','NOLAN','2547289890','AUXERRE','07 57 70 88 44','brage.nolan@lbfc-foot.fr','STADE AUXERROIS'],
        ['BRANCO','VITOR','891817996','RACINE','06 26 52 09 95','branco.vitor@lbfc-foot.fr','U S VERGIGNY ST FLORENTIN PORT'],
        ['BRAVO','Loris','2548467163','COURTENAY','06 62 37 91 69','bravo.loris@lbfc-foot.fr','GATINAIS'],
        ['BRIDE','J.ALEX','2548172102','PONT/YONNE','06 26 06 00 81','bride.johann@lbfc-foot.fr','F.C. SENS'],
        ['BRUNET','THIBAULT','2546488483','VILLEFARGEAU','07 85 98 98 81','brunet.thibault@lbfc-foot.fr','E.S. APPOIGNY'],
        ['CANDON','HUGO','2546348558','MAGNY','06 32 14 52 94','candon.hugo@lbfc-foot.fr','A.S. MAGNY'],
        ['CARBOGNIN','JAROD','9603837904','ANCY LE FRANC','06 87 57 64 85','carbognin.jarod@lbfc-foot.fr','US RAVIERES'],
        ['CARROUE','GABRIEL','2546766803','PERRIGNY','06 95 79 52 28','carroue.gabriel@lbfc-foot.fr','STADE AUXERROIS'],
        ['CHATON','AURELIEN','891815242','ST BRIS','06 99 42 86 67','chaton.aurelien@lbfc-foot.fr','ALL.S. ST BRIS LE VINEUX'],
        ['CHIHI','ABDELFATTAH','801816122','EVRY','06 22 14 45 11','chihi.abdelfattah@lbfc-foot.fr','F.C. SENS'],
        ['COHEN','LUCAS','2548534857','ST SEROTIN','06 14 17 78 59','cohen.lucas@lbfc-foot.fr','ST SEROTIN'],
        ['COSTA','THIBAULT','1766210096','FLOGNY LA CHAP','06 27 41 02 79','costa.thibault@lbfc-foot.fr','U.S. DE VARENNES'],
        ['COTTENOT','AXEL','2543423642','AUXERRE','06 74 05 98 92','cottenot.axel@lbfc-foot.fr','AS DE NEY'],
        ['COUSON','ETHAN','2546972465','LINDRY','07 82 31 03 80','couson.ethan@lbfc-foot.fr','CHARBUY FLEURY'],
        ['DALEGRE','ALEXIS','2544916783','AUXERRE','06 70 96 76 56','dalegre.alexis@lbfc-foot.fr','ENTENTE FLORENTINOISE F C'],
        ['DAVID','STEVENS','1032111743','FLEYS','06 47 13 69 26','david.stevens@lbfc-foot.fr','U.S. DE VARENNES'],
        ['DE SMET','VALENTIN','2547536142','AUXERRE','06 42 38 13 40','desmet.valentin@lbfc-foot.fr','A.J. AUXERRE'],
        ['DELANOUE BLANQUET','ANTOINE','9603599921','CHAMPIGNELLES','06 86 28 40 77','delanoue-blanquet.antoine@lbfc-foot.fr','ST FARGEAU S.F.'],
        ['DELPHIN','ALAIN','1142421930','PONT/YONNE','06 75 30 65 10','delphin.alain@lbfc-foot.fr','PONT'],
        ['DIAS DE ALMEIDA','STEPHANE','891812599','LE VAL DOCRE','06 23 39 08 49','diasdealmeida.stephane@lbfc-foot.fr','F.C. COULANGES LA VINEUSE'],
        ['DIDIER','PHILIPPE','881812720','AUXERRE','06 74 23 05 33','didier.philippe@lbfc-foot.fr','A.J. AUXERRE'],
        ['DO FUNDO','SUNNY','2546249422','VENOY','06 37 62 96 00','dofundo.sunny@lbfc-foot.fr','F.C. DE MONETEAU'],
        ['DUFOUR','Tymeo','9603504742','LADUZ','06 30 97 72 96','dufour.tymeo@lbfc-foot.fr','STADE AUXERROIS'],
        ['DUPONT','LUKE','821829153','MOULINS/OUANNE','06 45 70 53 35','dupont.luke@lbfc-foot.fr','US TOUCY'],
        ['DUVOIE','GUILLAUME','2545105693','PAILLY','07 85 56 37 78','duvoie.guillaume@lbfc-foot.fr','S.C. MALAY LE GRAND'],
        ['EL ALLALI EL SAFI','REDA','9604948767','','07 84 79 79 81','redaelallalielmiri@gmail.com','SPORTING CLUB SENONAIS'],
        ['EL HAYANI LAZZOAUI','OMAR','9602955377','AUXERRE','07 83 77 38 55','el-hayani-lazzaoui.omar@lbfc-foot.fr','ST GEORGES SUR BAULCHE'],
        ['FELTES','LOGAN','2547778533','HERY','06 71 25 42 43','feltes.logan@lbfc-foot.fr','A.S. DE GURGY'],
        ['FELTES','NOLAN','2547778511','HERY','06 89 89 30 02','feltes.nolan@lbfc-foot.fr','A.S. DE GURGY'],
        ['FERNANDES CARVALHO','ELODIE','2547500838','VERGIGNY','06 78 26 96 11','fernandes-carvalho.elodie@lbfc-foot.fr','A.S. MONTOISE'],
        ['FERNANDES CARVALHO','ROGERIO','2546612116','VERGIGNY','07 71 03 25 31','fernandescarvalho.rogerio@lbfc-foot.fr','A.S. MONTOISE'],
        ['FONSECA','NOAH','9604031833','CHESSY LES PRES','06 60 11 62 31','fonseca.noah@lbfc-foot.fr','U.S. DE VARENNES'],
        ['FOURNIER','LUCAS','9603448660','','07 57 63 21 24','stephanie.charrier89@gmail.com','US JOIGNY'],
        ['FOUQUIN','PAUL','2548017991','BUTTEAUX','06 80 20 00 63','fouquin.paul@lbfc-foot.fr','ENTENTE FLORENTINOISE'],
        ['FRAPPIN','YOHANN','841821638','AUXERRE','06 22 10 19 13','frappin.yohann@lbfc-foot.fr','STADE AUXERROIS'],
        ['FRONT','ENZO','2546091114','MONTHOLON','06 15 48 65 61','front.enzo@lbfc-foot.fr','A.J. AUXERRE'],
        ['GARCIA','JEAN LUC','838404163','PARON','06 63 86 95 39','garcia.jean-luc@lbfc-foot.fr','PARON F. C.'],
        ['GASSELIN','RUDDY','9604248166','TONNERRE','06 69 40 14 33','gasselin.ruddy@lbfc.fr','UNION FOOTBALL TONNERROIS'],
        ['GAUTHIER','Casey','9604009511','CHAMPIGNY','06 20 97 40 70','gauthier.casey@lbfc-foot.fr','CHAMPIGNY'],
        ['GIL','ALEXIS','2545129451','APPOIGNY','07 83 75 86 26','gil.alexis@lbfc-foot.fr','E.S. APPOIGNY'],
        ['GIRARD GLEIZES','DAMIEN','2547422090','ROUVRAY','06 68 70 94 77','girard-gleizes.damien@lbfc-foot.fr','ET.S. DHERY'],
        ['GOLISSET','AXEL','2543752196','VILLENEUVE SUR','07 61 89 49 43','golisset.axel@lbfc-foot.fr','U.S. JOIGNY'],
        ['GONCALVES','ANDREA','2548495709','JAULGES','06 27 37 77 36','goncalves.andrea@lbfc-foot.fr','U.S. DE VARENNES'],
        ['GOSNET','FRANCK','811827067','VERMENTON','06 70 31 17 10','gosnet.franck@lbfc-foot.fr','U.S. VERMENTONNAISE'],
        ['GOURIER','MATHIS','9604085154','SAUVIGNY','06 18 22 48 16','gourier.mathis@lbfc-foot.fr','A.S. MAGNY'],
        ['GRAILLER','ALBAN','2027123479','MIGENNES','06 44 10 13 14','grailler.alban@lbfc-foot.fr','A.J. AUXERRE'],
        ['GRENON','Ethan','9602515476','TOUCY','06 42 77 05 95','grenon.ethan@lbfc-foot.fr','TOUCYCOISE'],
        ['GRENON','Eddy','821832850','TOUCY','06 42 06 96 63','grenon.eddy@lbfc-foot.fr','TOUCYCOISE'],
        ['GRIVET','PATRICK','810287904','BRIENON SUR ARMANCON','06 48 30 98 65','grivet.patrick@lbfc-foot.fr','A.J. AUXERRE'],
        ['GUICHETEAU','RUDY','2543564023','SAVIGNY SUR CLAIRIS','06 03 88 28 37','guicheteau.rudy@lbfc-foot.fr','AM. FRANCO PORTUGAISE SENS'],
        ['GUIDOU','QUENTIN','811826435','DIJON','06 01 00 44 55','guidou.quentin@lbfc-foot.fr','ET.S. DHERY'],
        ['HALLAL','RIDA','2546619709','BAZARNES','06 69 65 70 66','hallal.rida@lbfc-foot.fr','C.AV. ST GEORGES'],
        ['HENNOQUE','CHARLY','2548232054','COULANGES','06 21 93 62 20','hennoque.charly@lbfc-foot.fr','F.C. DE CHAMPS'],
        ['HOUCHOT','LUDOVIC','838415095','MONTHOLON','06 89 88 97 36','houchot.ludovic@lbfc-foot.fr','AILLANT SP.'],
        ['HUBLER','Valentin','9602445862','JOUX LA VILLE','06 15 96 19 29','hubler.valentin@lbfc-foot.fr','ECN'],
        ['HUEL','THEO','2545566347','MOLOSMES','06 46 49 44 62','huel.theo@lbfc-foot.fr','UNION FOOTBALL TONNERROIS'],
        ['IMBERT','TITOUAN','9604013439','','06 61 90 02 56','nicolas.imbert.free@gmail.com','MONETEAU'],
        ['JOSSIER','LORIS','2547018049','VILLEFARGEAU','07 87 09 48 26','jossier.loris@lbfc-foot.fr','F. C. DE CHEVANNES'],
        ['KARAVELIEV','MEHMET','2548405796','TONNERRE','06 71 87 82 82','karaveliev.mehmet@lbfc-foot.fr','UNION FOOTBALL TONNERROIS'],
        ['KHALLOUK','MOHAMED','838416553','ST FLORENTIN','06 52 55 21 90','khallouk.mohamed@lbfc-foot.fr','ENTENTE FLORENTINOISE F C'],
        ['KONE','ABOUBACAR','9604398306','AVALLON','07 53 22 68 83','kone.aboubacar@lbfc-foot.fr','AVALLON F C OLYMPIQUE'],
        ['LAAGUIR','MEHDI','2547407157','','06 30 46 12 59','mehdilaaguir@gmail.com','SPORTING CLUB SENONAIS'],
        ['LAHAYE','DAVID','861811927','LA CELLE ST CYR','06 10 97 63 02','lahaye.david@lbfc-foot.fr','F. C. DU GATINAIS'],
        ['LAMBLIN','HUGO','2548176784','CHABLIS','07 88 39 85 82','lamblin.hugo@lbfc-foot.fr','STADE AUXERROIS'],
        ['LAUNAY','JULIEN','820658868','LIGNY LE CHATEAU','06 14 06 32 95','launay.julien@lbfc-foot.fr','A.J. AUXERRE'],
        ['LE MOING','JULIEN','851817796','CHASTELLUX SUR CURE','06 78 12 58 09','lemoing.julien@lbfc-foot.fr','F. C. QUARRE ST GERMAIN'],
        ['LE STUM','LOHAN','9603266466','DOMATS','06 30 03 90 78','lestum.lohan@lbfc-foot.fr','F.C. SENS'],
        ['LEBRET','Tilio','9604400286','APPOIGNY','07 86 36 27 60','lebret.tilio@lbfc-foot.fr','E.S. APPOIGNY'],
        ['LEMASSON','JULIEN','871818537','CHENY','06 50 76 03 30','lemasson.julien@lbfc-foot.fr','A. ANIMATION C.S. DE CHENY'],
        ['LEPRUN','MAXIME','2548109532','VENOY','06 81 84 09 25','leprun.maxime@lbfc-foot.fr','A.S. MONTOISE'],
        ['LEUNGOUE TEKALE','JONATHAN','2318043353','ROSOY','06 79 80 74 23','leungoue-tekale.jonathan@lbfc-foot.fr','PARON F. C.'],
        ['LOBBE','NATHAN','2548014198','MONETEAU','06 88 13 99 85','lobbe.nathan@lbfc-foot.fr','F.C. DE MONETEAU'],
        ['LOPEZ','FREDERIC','820364191','CHAMVRES','06 26 94 33 28','lopez.frederic@lbfc-foot.fr','U.S. JOIGNY'],
        ['LUQUET','ROMARICK','9604897170','LA CHAPELLE/OREUSE','06 99 37 05 55','luquet.romarick@lbfc-foot.fr','A.F.C. CHAMPIGNY S/YONNE'],
        ['LURIER','MAXIME','2547353773','AUXERRE','06 21 86 26 69','lurier.maxime@lbfc-foot.fr','E.S. APPOIGNY'],
        ['MADELEINAT','VALENTIN','2548585319','','06 77 18 20 05','madeleinat.folleas@orange.fr','FC QUARRE ST GERMAIN'],
        ['MALDOU','ADIL','801819723','GRON','06 50 71 70 82','maldou.adil@lbfc-foot.fr','US DIONYSIENNE ST DENIS SENS'],
        ['MALKI','HAKIM','838418534','SEIGNELAY','06 69 14 21 13','malki.hakim@lbfc-foot.fr','ENTENTE FLORENTINOISE'],
        ['MANCINI','VALENTIN','9604438232','VILLEFARGEAU','06 76 95 41 36','mancini.valentin@lbfc-foot.fr','A.J. AUXERRE'],
        ['MARY','PASCAL','841814012','CRY','06 27 57 40 12','mary.pascal@lbfc-foot.fr','FOY.RUR. DE TANLAY'],
        ['MASSENOT','MATHIAS','9602518389','','06 02 15 86 89','laurentmassenot21@gmail.com','AS MAGNY'],
        ['MAZZA','LEA','2548565176','CHENY','07 80 28 80 73','mazza.lea@lbfc-foot.fr','A.S. DE GURGY'],
        ['MEBROUK','ABDEL','9603244395','SENS','06 12 19 04 62','mebrouk.abdel@lbfc-foot.fr','SENS FRANCO. PORTUGAIS'],
        ['MENDES','SCOTTY','2308083662','PASSY','07 82 37 37 25','mendes.scotty@lbfc-foot.fr','GRON VERON'],
        ['MESSAOUDI','DJAMAL','871815171','PAILLY','06 24 65 01 89','messaoudi.djamal@lbfc-foot.fr','F.C. SENS'],
        ['MESSINA','ANDERSON','9604409633','LEZINNES','06 41 55 12 80','messina.anderson@lbfc-foot.fr','UF TONNERROIS'],
        ['MUSIJ','LAURENT','810287522','AUXERRE','06 31 03 92 68','musij.laurent@lbfc-foot.fr','A.J. AUXERRE'],
        ['OUJBBOUR','SAFOUANE','2548524214','','06 51 94 12 48','noops20@hotmail.com','AUXERRE SPORTS CITOYEN'],
        ['OULDEMMOU','Mohamed','2548145984','ST MARTIN DU TERTRE','06 10 47 50 11','ouldemmou.mohamed@lbfc-foot.fr','SENS FP'],
        ['PACOT','AXEL','2546189398','TONNERRE','07 87 41 87 74','pacot.axel@lbfc-foot.fr','UNION FOOTBALL TONNERROIS'],
        ['PAGIS','MAXIME','2546485821','GY L EVEQUE','07 61 42 90 54','pagis.maxime@lbfc-foot.fr','AJ AUXERRE'],
        ['PALANCA','JULIEN','838413571','COLLEMIERS','06 99 18 16 99','palanca.julien@lbfc-foot.fr','PARON F. C.'],
        ['PETIT','NICOLAS','430637825','CHAILLEY','06 76 94 43 05','petit.nicolas@lbfc-foot.fr','ENTENTE FLORENTINOISE F C'],
        ['PIAT','LENNY','2546562707','JAULGES','06 89 05 60 69','piat.lenny@lbfc-foot.fr','A.S. CHABLISIENNE'],
        ['PIERRU','JEREMY','2545993773','LE VAL DOCRE','06 74 90 07 85','pierru.jeremy@lbfc-foot.fr','AILLANT SP.'],
        ['PINCHON','CEDRIC','851819032','CRUZY','06 64 85 88 73','pinchon.cedric@lbfc-foot.fr','RAVIERES'],
        ['PINLON','PIERRE','2544984253','GRON','06 88 65 06 30','pinlon.pierre@lbfc-foot.fr','S.C. MALAY LE GRAND'],
        ['QOJI','MAISSANE','9602563068','AUXERRE','07 69 63 92 67','qoji.maissane@lbfc-foot.fr','A.J. AUXERRE'],
        ['QOJI','MOHAMMED','2543669618','AUXERRE','06 59 65 95 23','qoji.mohammed@lbfc-foot.fr','AJ AUXERRE'],
        ['RAISON','CLEMENT','2548430827','BRION','06 34 62 69 64','raison.clement@lbfc-foot.fr','ES APPOIGNY'],
        ['RAPINEAU','FREDERIC','899185043','AUXERRE','07 82 78 95 94','rapineau.frederic@lbfc-foot.fr','CHAMPS SUR YONNE'],
        ['RICHARD','ALEXIS','891813378','PONT/YONNE','06 77 88 02 57','alexis.richard25@orange.fr','US DIONYSIENNE ST DENIS SENS'],
        ['SALMON','PASCALE','891816589','ST ANDRE EN TERRE PLAINE','06 83 23 46 76','salmon.pascale@lbfc-foot.fr','ALL.S. COURSON'],
        ['SEHOULI','SAMY','2548172371','ST FLORENTIN','06 51 54 37 90','sehouli.samy@lbfc-foot.fr','ENTENTE FLORENTINOISE'],
        ['SELLIER','THOMAS','2545532981','AUXERRE','06 63 29 53 74','sellier.thomas@lbfc-foot.fr','AJ AUXERRE'],
        ['SOARES','JEAN MATTHIEU','2543830759','CUSSY LE FORGES','07 70 07 66 25','soares.jean-mathieu@lbfc-foot.fr','AVALLON'],
        ['SOYER','Evan','2548486848','CHENY','06 80 36 70 84','soyer.evan@lbfc-foot.fr','A.S. DE GURGY'],
        ['STANISIC','GORAN','1002132293','MALAY LE GRAND','06 63 41 06 87','stanisic.goran@lbfc-foot.fr','F.C. SENS'],
        ['SZELAG','MICHEL','2545052258','MALAY LE PETIT','06 07 17 40 85','szelag.michel@lbfc-foot.fr','PARON F. C.'],
        ['TABOUREAU','GILLES','899185939','CHABLIS','06 32 08 05 33','taboureau.gilles@lbfc-foot.fr','A.S. CHABLISIENNE'],
        ['TAPSOBA','ISSIAKA','9605340489','','07 78 55 97 15','tapsobauzumaki@gmail.com','ST GEORGES'],
        ['TARATTE','Gaetan','2543779907','CHATEL GERARD','06 08 58 32 81','gaetan.taratte@gmail.com','ECN'],
        ['TATLIGUN','ALI','2545054478','SENS','06 59 25 31 75','tatligun.ali@lbfc-foot.fr','US DIONYSIENNE ST DENIS SENS'],
        ['THOMAS','JULIEN','820580121','VALRAVILLON','06 32 35 00 88','thomas.julien@lbfc-foot.fr','ST FARGEAU S.F.'],
        ['TUPINIER','MAXIME','2546739900','','06 87 22 62 46','maxime.tupinier@edu.univ-fcomte.fr','AS MAGNY'],
        ['VERGER','MATHEO','2546153202','VINNEUF','07 62 12 28 74','verger.matheo@lbfc-foot.fr','A.F.C. CHAMPIGNY S/YONNE'],
        ['VERMESSE','Hugo','9602438982','BONNARD','06 07 70 04 30','vermesse.hugo@lbfc-foot.fr','A.J AUXERRE'],
        ['VIE','GUILLAUME','891814394','AUXERRE','06 01 06 49 06','vie.guillaume@lbfc-foot.fr','C.AV. ST GEORGES'],
        ['YILDIRIM','MEHMET','820463231','MAILLOT','07 45 12 33 32','yildirim.mehmet@lbfc-foot.fr','AM. FRANCO PORTUGAISE SENS'],
        ['YILGIN','ENES','2547267820','CHASSIGNY','06 19 41 77 19','yilgin.enes@lbfc-foot.fr','AVALLON F C OLYMPIQUE'],
        ['ZAKRANI','HICHAM','851819176','SENS','06 63 47 90 66','zakrani.hicham@lbfc-foot.fr','F.C. SENS']
      ];
      arbs.forEach(a => ins2.run(...a));
      ins2.finalize();
      console.log('✅ Arbitres seedés:', arbs.length);
    }
  });

// Nettoyage tokens expirés
setInterval(() => {
  db.run("DELETE FROM refresh_tokens WHERE expires_at < datetime('now')");
}, 3600000);

// ═══════════════════════════════════════
//  APP EXPRESS
// ═══════════════════════════════════════
const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ═══════════════════════════════════════
//  HELPERS AUTH
// ═══════════════════════════════════════
const signAccess  = u => jwt.sign({ id: u.id, username: u.username, role: u.role, nom: u.nom }, JWT_SECRET, { expiresIn: '2h' });
const signRefresh = u => jwt.sign({ id: u.id }, JWT_REFRESH_SECRET, { expiresIn: '7d' });

async function issueTokens(user) {
  const access  = signAccess(user);
  const refresh = signRefresh(user);
  await dbRun(
    "INSERT OR REPLACE INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, datetime('now', '+7 days'))",
    [user.id, refresh]
  );
  return { accessToken: access, refreshToken: refresh };
}

function authMiddleware(req, res, next) {
  const raw = req.headers.authorization || '';
  const token = raw.startsWith('Bearer ') ? raw.slice(7) : '';
  if (!token) return res.status(401).json({ error: { message: 'Token manquant' } });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: { message: 'Token invalide ou expiré' } });
  }
}

const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user?.role))
    return res.status(403).json({ error: { message: 'Accès refusé' } });
  next();
};

// ═══════════════════════════════════════
//  RATE LIMITERS
// ═══════════════════════════════════════
const authLimiter   = rateLimit({ windowMs: 900000, max: 20, message: { error: { message: 'Trop de tentatives.' } } });
const claudeLimiter = rateLimit({ windowMs: 60000,  max: 40, message: { error: { message: 'Limite IA atteinte.' } } });

// ═══════════════════════════════════════
//  HEALTH
// ═══════════════════════════════════════
app.get('/api/health', (req, res) =>
  res.json({ status: 'ok', version: '2.1.0', timestamp: new Date().toISOString() }));

// ═══════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════
app.get('/api/auth/session', authMiddleware, (req, res) =>
  res.json({ data: req.user }));

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password)
      return res.status(400).json({ error: { message: 'Identifiant et mot de passe requis.' } });
    const user = await dbGet('SELECT * FROM users WHERE username = ? AND actif = 1', [username]);
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: { message: 'Identifiant ou mot de passe incorrect.' } });
    await dbRun("UPDATE users SET last_login = datetime('now') WHERE id = ?", [user.id]);
    await dbRun('INSERT INTO conn_log (user_id, username, role, action, ip) VALUES (?, ?, ?, ?, ?)',
      [user.id, user.username, user.role, 'login', req.ip]);
    const tokens = await issueTokens(user);
    res.json({ data: { ...tokens, role: user.role, nom: user.nom, id: user.id } });
  } catch (e) { res.status(500).json({ error: { message: e.message } }); }
});

app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.status(401).json({ error: { message: 'Refresh token manquant.' } });
    const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    const stored  = await dbGet(
      "SELECT * FROM refresh_tokens WHERE token = ? AND expires_at > datetime('now')", [refreshToken]);
    if (!stored) return res.status(401).json({ error: { message: 'Token révoqué.' } });
    const user = await dbGet('SELECT * FROM users WHERE id = ? AND actif = 1', [payload.id]);
    if (!user) return res.status(401).json({ error: { message: 'Compte introuvable.' } });
    res.json({ data: { accessToken: signAccess(user) } });
  } catch { res.status(401).json({ error: { message: 'Refresh token invalide.' } }); }
});

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  const { refreshToken } = req.body || {};
  if (refreshToken) await dbRun('DELETE FROM refresh_tokens WHERE token = ?', [refreshToken]);
  res.json({ success: true });
});

// ═══════════════════════════════════════
//  REPORTS
// ═══════════════════════════════════════
function parseReport(r) {
  const data = (() => { try { return JSON.parse(r.data_json); } catch { return {}; } })();
  return {
    id: r.ext_id, arbitre: r.arbitre, arbitreEmail: r.arb_email, obsNom: r.obs_nom,
    categorie: r.categorie, competition: r.competition, equipes: r.equipes,
    date: r.date_match, score: r.score, note20: r.note_20, note100: r.note_100,
    statut: r.statut, auteurId: r.auteur_id, auteurNom: r.auteur_nom,
    createdAt: r.created_at, updatedAt: r.updated_at, ...data
  };
}

app.get('/api/reports', authMiddleware, async (req, res) => {
  const rows = await dbAll("SELECT * FROM reports WHERE statut != 'DRAFT' ORDER BY created_at DESC");
  res.json({ data: rows.map(parseReport) });
});

app.get('/api/reports/:id', authMiddleware, async (req, res) => {
  const r = await dbGet('SELECT * FROM reports WHERE ext_id = ?', [req.params.id]);
  if (!r) return res.status(404).json({ error: { message: 'Rapport introuvable.' } });
  res.json({ data: parseReport(r) });
});

app.post('/api/reports', authMiddleware, async (req, res) => {
  try {
    const rpt = req.body;
    const extId = String(rpt.id || Date.now());
    await dbRun(
      `INSERT OR REPLACE INTO reports
       (ext_id, arbitre, arb_email, obs_nom, categorie, competition, equipes,
        date_match, score, note_20, note_100, statut, data_json, auteur_id, auteur_nom, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
      [extId, rpt.arbitre||'', rpt.arbitreEmail||'', rpt.obsNom||'',
       rpt.categorie||'', rpt.competition||'', rpt.equipes||'',
       rpt.date||'', rpt.score||'0-0', rpt.note20||0, rpt.note100||0,
       rpt.statut||'🟡 En attente de validation',
       JSON.stringify(rpt), req.user.id, req.user.nom]
    );
    res.json({ success: true, id: extId });
  } catch (e) { res.status(500).json({ error: { message: e.message } }); }
});

app.put('/api/reports/:id', authMiddleware, requireRole('admin','gest'), async (req, res) => {
  try {
    const rpt = req.body;
    await dbRun(
      `UPDATE reports SET arbitre=?, arb_email=?, obs_nom=?, categorie=?, competition=?,
       equipes=?, date_match=?, score=?, note_20=?, note_100=?, statut=?, data_json=?,
       updated_at=datetime('now') WHERE ext_id=?`,
      [rpt.arbitre||'', rpt.arbitreEmail||'', rpt.obsNom||'', rpt.categorie||'',
       rpt.competition||'', rpt.equipes||'', rpt.date||'', rpt.score||'0-0',
       rpt.note20||0, rpt.note100||0, rpt.statut||'', JSON.stringify(rpt), req.params.id]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: { message: e.message } }); }
});

app.patch('/api/reports/:id/statut', authMiddleware, requireRole('admin','gest'), async (req, res) => {
  await dbRun("UPDATE reports SET statut=?, updated_at=datetime('now') WHERE ext_id=?",
    [req.body.statut, req.params.id]);
  res.json({ success: true });
});

app.delete('/api/reports/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  await dbRun('DELETE FROM reports WHERE ext_id = ?', [req.params.id]);
  res.json({ success: true });
});

// ═══════════════════════════════════════
//  BROUILLON
// ═══════════════════════════════════════
app.get('/api/draft', authMiddleware, async (req, res) => {
  const row = await dbGet("SELECT data_json FROM reports WHERE ext_id = ? AND statut = 'DRAFT'",
    [`draft_${req.user.id}`]);
  res.json({ data: row ? JSON.parse(row.data_json) : null });
});

app.post('/api/draft', authMiddleware, async (req, res) => {
  const extId = `draft_${req.user.id}`;
  await dbRun(
    "INSERT OR REPLACE INTO reports (ext_id, statut, data_json, auteur_id, auteur_nom, updated_at) VALUES (?, 'DRAFT', ?, ?, ?, datetime('now'))",
    [extId, JSON.stringify(req.body), req.user.id, req.user.nom]
  );
  res.json({ success: true });
});

app.delete('/api/draft', authMiddleware, async (req, res) => {
  await dbRun('DELETE FROM reports WHERE ext_id = ?', [`draft_${req.user.id}`]);
  res.json({ success: true });
});

// ═══════════════════════════════════════
//  USERS (admin)
// ═══════════════════════════════════════
app.get('/api/users', authMiddleware, requireRole('admin'), async (req, res) => {
  const users = await dbAll('SELECT id, username, role, nom, email, actif, created_at, last_login FROM users ORDER BY id');
  res.json({ data: users });
});

app.post('/api/users', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const { username, password, role, nom, email } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: { message: 'Identifiant et mot de passe requis.' } });
    if (!['obs','gest','admin'].includes(role)) return res.status(400).json({ error: { message: 'Rôle invalide.' } });
    const result = await dbRun('INSERT INTO users (username, password, role, nom, email) VALUES (?, ?, ?, ?, ?)',
      [username, bcrypt.hashSync(password, 12), role, nom||'', email||'']);
    res.json({ success: true, id: result.lastID });
  } catch { res.status(409).json({ error: { message: 'Identifiant déjà utilisé.' } }); }
});

app.put('/api/users/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { username, role, nom, email, actif, password } = req.body || {};
  if (password) {
    await dbRun('UPDATE users SET username=?, role=?, nom=?, email=?, actif=?, password=? WHERE id=?',
      [username, role, nom||'', email||'', actif?1:0, bcrypt.hashSync(password,12), req.params.id]);
  } else {
    await dbRun('UPDATE users SET username=?, role=?, nom=?, email=?, actif=? WHERE id=?',
      [username, role, nom||'', email||'', actif?1:0, req.params.id]);
  }
  res.json({ success: true });
});

app.delete('/api/users/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  if (parseInt(req.params.id) === req.user.id)
    return res.status(400).json({ error: { message: 'Impossible de supprimer votre propre compte.' } });
  await dbRun('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// ═══════════════════════════════════════
//  JOURNAL CONNEXIONS (admin)
// ═══════════════════════════════════════
app.get('/api/connlog', authMiddleware, requireRole('admin'), async (req, res) => {
  const log = await dbAll('SELECT * FROM conn_log ORDER BY timestamp DESC LIMIT 100');
  res.json({ data: log });
});

// ═══════════════════════════════════════
//  PROXY GEMINI (remplace Claude)
// ═══════════════════════════════════════
app.post('/api/claude', authMiddleware, claudeLimiter, async (req, res) => {
  if (!GEMINI_API_KEY)
    return res.status(503).json({ error: { message: 'Clé API Gemini non configurée.' } });
  try {
    // Convertir format Claude → format Gemini
    const messages = req.body.messages || [];
    const contents = messages.map(m => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: typeof m.content === 'string' ? m.content : JSON.stringify(m.content) }]
    }));
    const maxTokens = req.body.max_tokens || 1000;

    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents,
          generationConfig: { maxOutputTokens: maxTokens }
        })
      }
    );
    const data = await response.json();

    // Convertir réponse Gemini → format Claude (pour ne pas changer le frontend)
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    res.json({ content: [{ type: 'text', text }] });

  } catch (e) { res.status(500).json({ error: { message: 'Erreur proxy Gemini: ' + e.message } }); }
});

// ═══════════════════════════════════════
//  ARBITRES
// ═══════════════════════════════════════
app.get('/api/arbitres', authMiddleware, async (req, res) => {
  const rows = await dbAll('SELECT * FROM arbitres ORDER BY nom, prenom');
  res.json({ data: rows });
});

app.post('/api/arbitres', authMiddleware, requireRole('gest','admin'), async (req, res) => {
  try {
    const { nom, prenom, licence, localite, telephone, email, club } = req.body || {};
    if (!nom) return res.status(400).json({ error: { message: 'Le nom est requis.' } });
    const result = await dbRun(
      'INSERT INTO arbitres (nom,prenom,licence,localite,telephone,email,club) VALUES (?,?,?,?,?,?,?)',
      [nom.toUpperCase(), prenom||'', licence||'', localite||'', telephone||'', email||'', club||'']
    );
    res.json({ success: true, id: result.lastID });
  } catch(e) { res.status(500).json({ error: { message: e.message } }); }
});

app.put('/api/arbitres/:id', authMiddleware, requireRole('gest','admin'), async (req, res) => {
  const { nom, prenom, licence, localite, telephone, email, club } = req.body || {};
  await dbRun(
    "UPDATE arbitres SET nom=?,prenom=?,licence=?,localite=?,telephone=?,email=?,club=?,updated_at=datetime('now') WHERE id=?",
    [nom.toUpperCase(), prenom||'', licence||'', localite||'', telephone||'', email||'', club||'', req.params.id]
  );
  res.json({ success: true });
});

app.delete('/api/arbitres/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  await dbRun('DELETE FROM arbitres WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// ═══════════════════════════════════════
//  FALLBACK SPA
// ═══════════════════════════════════════
app.get('*', (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ═══════════════════════════════════════
//  START
// ═══════════════════════════════════════
app.listen(PORT, () => {
  console.log(`🟡 District BFC — http://localhost:${PORT}`);
  console.log(`   DB : ${DB_PATH}`);
  console.log(`   IA : ${GEMINI_API_KEY ? '✅ Gemini' : '⚠️  GEMINI_API_KEY non configurée'}`);
});
