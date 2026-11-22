const assert=require("node:assert/strict");const {readFileSync}=require("node:fs");const path=require("node:path");const test=require("node:test");const vm=require("node:vm");const ts=require("typescript");
const exportsObject={};const source=readFileSync(path.join(__dirname,"../src/gameStatus.ts"),"utf8");const code=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS}}).outputText;vm.runInNewContext(code,{exports:exportsObject});const {gameStatus,gameConnectionNote}=exportsObject;
const base={engineRunning:true,activeMode:"balanced",fresh:true,targets:["custom"],error:"",adaptive:{helping:0,responsive:0}};
test("network replies never promise a launched game",()=>assert.equal(gameStatus({...base,adaptive:{helping:0,responsive:8}},false),"Обнаружен сетевой обмен"));
test("a driver error overrides previous traffic",()=>assert.equal(gameStatus({...base,error:"WinDivert — код 1058",adaptive:{helping:1,responsive:8}},false),"Нужна проверка"));
test("stale traffic is not reported as current",()=>assert.equal(gameStatus({...base,fresh:false,adaptive:{responsive:8}},false),"Ожидаем движок"));
test("launcher discovery and stopped engine stay distinct",()=>{assert.equal(gameStatus(base,false),"Игра / лаунчер обнаружены");assert.equal(gameStatus({...base,engineRunning:false},false),"Выключен");});

test("missing TLS data overrides retries and unrelated healthy traffic",()=>assert.equal(gameStatus({...base,transport:{stage:"tls_unanswered"},adaptive:{helping:2,responsive:8}},false),"Нет ответа на TLS-запрос"));
test("tunnel traffic identifies the route without promising login",()=>assert.equal(gameStatus({...base,stats:{tunnel:true},transport:{stage:"exchanging",responding:2}},false),"Есть обмен через игровой маршрут"));
test("stale tunnel evidence never supplies a connection diagnosis",()=>assert.equal(gameConnectionNote({...base,fresh:false,stats:{tunnel:true},transport:{stage:"tls_closed"}}),""));
