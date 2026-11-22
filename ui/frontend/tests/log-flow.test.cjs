const assert=require("node:assert/strict");const {readFileSync}=require("node:fs");const path=require("node:path");const test=require("node:test");const vm=require("node:vm");const ts=require("typescript");
const exportsObject={};const source=readFileSync(path.join(__dirname,"../src/logFlow.ts"),"utf8");const code=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS}}).outputText;vm.runInNewContext(code,{exports:exportsObject});const {advance,emptyFlow,resume,ROWS,STEP}=exportsObject;
const lines=["a","b","c"];const ids=(flow)=>Array.from(flow.rows,(row)=>row.id);
test("a new session opens with a few lines",()=>{const flow=resume(emptyFlow(),"s1",lines,1000);assert.deepEqual(ids(flow),[0,1,2,3,4,5]);assert.equal(flow.session,"s1");});
test("coming back within one step keeps the journal where it was",()=>{const flow=resume(emptyFlow(),"s1",lines,1000);assert.equal(resume(flow,"s1",lines,1000+STEP-1),flow);});
test("coming back later continues from the same line instead of starting over",()=>{const flow=resume(resume(emptyFlow(),"s1",lines,1000),"s1",lines,1000+STEP*3+10);assert.deepEqual(ids(flow),[0,1,2,3,4,5,6,7,8]);assert.equal(flow.rows[8].text,"c");});
test("a long absence adds one screen of lines and drops the old ones",()=>{const flow=resume(resume(emptyFlow(),"s1",lines,1000),"s1",lines,1000+STEP*500);assert.equal(flow.rows.length,ROWS+1);assert.equal(flow.rows[0].id,6);assert.equal(flow.cursor,6+ROWS+1);});
test("another session starts the journal over",()=>assert.deepEqual(ids(resume(advance(resume(emptyFlow(),"s1",lines,1000),lines,2000,4),"s2",lines,3000)),[0,1,2,3,4,5]));
test("nothing is shown until there is something to say",()=>assert.equal(resume(emptyFlow(),"s1",[],1000).rows.length,0));
