WScript.LoadScriptFile("../../../../test/WasmSpec/testsuite/harness/wasm-constants.js")
WScript.LoadScriptFile("../../../../test/WasmSpec/testsuite/harness/wasm-module-builder.js")

function getRandomInt(min, max) {
        min = Math.ceil(min);
        max = Math.floor(max);
        return Math.floor(Math.random() * (max - min)) + min; //The maximum is exclusive and the minimum is inclusive
}

function getRandomIntInclusive(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min; //The maximum is inclusive and the minimum is inclusive 
}

function constructMemory(self) {
        if ( hasMemory )
                return;
        let initial = getRandomInt(0,16384);
        let maximum = getRandomInt(initial,65536);
        let isExport = getRandomIntInclusive(0,1);
        self.addMemory(initial, maximum, isExport);
        hasMemory = true
}

function constructStart(self) {
        let startId = getRandomInt(0, self.functions.length);
        addStart(startId)
        // Todo : start function signature must be sig_v_v 
}

function constructExplicitSection(self) {
        // Todo : addExplicitSection add anything you like
        return
}

function constructCustomSection(self){
        // Todo : addCustomSection(name, bytes) add anything you like
        return
}

function constructType(self){
        rltType = localTypes[getRandomInt(0, localTypes.length)];
        paramCount = getRandomInt(0, 1000);
        params = []
        for(let i=0; i<paramCount; i++)
        {
                params.push(localTypes[getRandomInt(0, localTypes.length)])
        }
        sig = makeSig(params,[rltType])
        addType(sig)
        return
}

var builder = new WasmModuleBuilder();

const localTypes = [kWasmI32 , kWasmI64, kWasmF32, kWasmF64, kWasmS128];
const constructors = ['addStart','addMemory','addExplicitSection','addCustomSection','addType'];

var typeTable = [];
var hasMemory = false;
var has_table = false;

for( var cc = 0; cc < getRandomInt(1, 1000); cc++)
{
        componentIndex =  getRandomIntInclusive(0,16);

        switch(componentIndex)
        {
                case 0:
                        constructStart(builder)    // addStart(start_index) 
                        break;
                case 1:
                        constructMemory(builder)  // addMemory(min, max, exported)  
                        break;
                case 2:
                        constructExplicitSection(builder) // addExplicitSection(bytes)  anything you like 
                        break;
                case 3:
                        constructCustomSection(builder) // addCustomSection(name, bytes)
                        break;
                case 4:
                        constructType(builder) //addType(type)
                        break;

        }
}