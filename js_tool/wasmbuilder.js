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
        self.addStart(startId)
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

function constructType(self, isAdd){
        let rltType = localTypes[getRandomInt(0, localTypes.length)];
        let paramCount = getRandomInt(0, 1000);
        let params = []
        for(let i=0; i<paramCount; i++)
        {
                params.push(localTypes[getRandomInt(0, localTypes.length)])
        }
        let sig = makeSig(params,[rltType])
        if (isAdd) self.addType(sig);
        return sig
}

function constructGlobal(self){
        let mutable = getRandomIntInclusive(0,1);
        let globalType = globalTypes[getRandomInt(0, globalTypes.length)];
        let isExport = getRandomIntInclusive(0,1);
        let isExport ? self.addGlobal( globalType, mutable).exportAs('global'+(gExportCount++) ): self.addGlobal( globalType, mutable);
}

function constructBody(self) {   // WasmFunctionBuilder
    self.addBody(data)    // anything you want
}

function constructFunction(self) {
        let isTyped = getRandomIntInclusive(0,1);
        let sig = constructType(self, false);
        let type = isTyped ? typeTable[getRandomInt(0,typeTable.length)] : sig;
        let fnName = 'func'+ (gFuncCount++);
        let func = self.addFunction(fnName, type);
        constructBody(func);
        funcTable.push({'name':fnName,'type':type});
        func.exportFunc()
}

// Todo : mix these function below, 
function constructImportFunc(self) {
        let sig = constructType(self, false);
        let importFnName =  'import'+(gImportCount++);
        self.addImport( 'mod', importFnName, sig);
        importFuncTable.push({'name':importFnName, 'type':sig })
}

function constructImportGlobal(self) {
        let globalType = globalTypes[getRandomInt(0, globalTypes.length)];
        let importGlobName =  'import'+(gImportCount++);
        self.addImportedGlobal( 'mod', importGlobName, globalType);
        importGlobalTable.push({'name':importGlobName, 'type':globalType });
}

function constructImportMemory(self) {
        if ( hasMemory )
                return;
        let initial = getRandomInt(0,16384);
        let maximum = getRandomInt(initial,65536);
        let importMemName = 'import'+(gImportCount++);
        self.addImportedMemory('mod', importMemName, initial, maximum);
        hasMemory = true;   // import WebAssembly.Memory anyway
}

function constructImportTable(self) {
        if ( hasTable )
                return;
        let initial = getRandomInt(0,16384);
        let maximum = getRandomInt(initial,65536);
        let importTableName = 'import'+(gImportCount++);
        self.addImportedTable('mod', importTableName, initial, maximum);
        hasTable = true;   // import WebAssembly.Table anyway
}

function constructImport(self) {
        switch (getRandomInt(0,3)) {
            case 0: constructImportFunc(self);break;
            case 1: constructImportGlobal(self);break;
            case 2: 
                if(hasMemory) 
                    constructImportFunc(self);
                else
                    elseconstructImportMemory(self);
                break;
            case 3: 
                if(hasTable)
                    constructImportGlobal(self);
                else
                    constructImportTable(self);
                break;
        }
}

function constructExport(self) {
    switch() {
        case 0:
    }
}

var builder = new WasmModuleBuilder();

const globalTypes = [kWasmI32 , kWasmI64, kWasmF32, kWasmF64];  // Todo : wbGetGlobal
const localTypes = [kWasmI32 , kWasmI64, kWasmF32, kWasmF64, kWasmS128];
const constructors = ['addStart','addMemory','addExplicitSection','addCustomSection','addType','addGlobal','addFunction','addImport'];
const Opcodes = [kExprUnreachable ,kExprNop ,kExprBlock ,kExprLoop ,kExprIf ,kExprElse ,kExprTry ,kExprCatch ,kExprThrow ,kExprEnd ,kExprBr ,kExprBrIf ,kExprBrTable ,kExprReturn ,kExprCallFunction ,kExprCallIndirect ,kExprDrop ,kExprSelect ,kExprGetLocal ,kExprSetLocal ,kExprTeeLocal ,kExprGetGlobal ,kExprSetGlobal ,kExprI32Const ,kExprI64Const ,kExprF32Const ,kExprF64Const ,kExprI32LoadMem ,kExprI64LoadMem ,kExprF32LoadMem ,kExprF64LoadMem ,kExprI32LoadMem8S ,kExprI32LoadMem8U ,kExprI32LoadMem16S ,kExprI32LoadMem16U ,kExprI64LoadMem8S ,kExprI64LoadMem8U ,kExprI64LoadMem16S ,kExprI64LoadMem16U ,kExprI64LoadMem32S ,kExprI64LoadMem32U ,kExprI32StoreMem ,kExprI64StoreMem ,kExprF32StoreMem ,kExprF64StoreMem ,kExprI32StoreMem8 ,kExprI32StoreMem16 ,kExprI64StoreMem8 ,kExprI64StoreMem16 ,kExprI64StoreMem32 ,kExprMemorySize ,kExprGrowMemory ,kExprI32Eqz ,kExprI32Eq ,kExprI32Ne ,kExprI32LtS ,kExprI32LtU ,kExprI32GtS ,kExprI32GtU ,kExprI32LeS ,kExprI32LeU ,kExprI32GeS ,kExprI32GeU ,kExprI64Eqz ,kExprI64Eq ,kExprI64Ne ,kExprI64LtS ,kExprI64LtU ,kExprI64GtS ,kExprI64GtU ,kExprI64LeS ,kExprI64LeU ,kExprI64GeS ,kExprI64GeU ,kExprF32Eq ,kExprF32Ne ,kExprF32Lt ,kExprF32Gt ,kExprF32Le ,kExprF32Ge ,kExprF64Eq ,kExprF64Ne ,kExprF64Lt ,kExprF64Gt ,kExprF64Le ,kExprF64Ge ,kExprI32Clz ,kExprI32Ctz ,kExprI32Popcnt ,kExprI32Add ,kExprI32Sub ,kExprI32Mul ,kExprI32DivS ,kExprI32DivU ,kExprI32RemS ,kExprI32RemU ,kExprI32And ,kExprI32Ior ,kExprI32Xor ,kExprI32Shl ,kExprI32ShrS ,kExprI32ShrU ,kExprI32Rol ,kExprI32Ror ,kExprI64Clz ,kExprI64Ctz ,kExprI64Popcnt ,kExprI64Add ,kExprI64Sub ,kExprI64Mul ,kExprI64DivS ,kExprI64DivU ,kExprI64RemS ,kExprI64RemU ,kExprI64And ,kExprI64Ior ,kExprI64Xor ,kExprI64Shl ,kExprI64ShrS ,kExprI64ShrU ,kExprI64Rol ,kExprI64Ror ,kExprF32Abs ,kExprF32Neg ,kExprF32Ceil ,kExprF32Floor ,kExprF32Trunc ,kExprF32NearestInt ,kExprF32Sqrt ,kExprF32Add ,kExprF32Sub ,kExprF32Mul ,kExprF32Div ,kExprF32Min ,kExprF32Max ,kExprF32CopySign ,kExprF64Abs ,kExprF64Neg ,kExprF64Ceil ,kExprF64Floor ,kExprF64Trunc ,kExprF64NearestInt ,kExprF64Sqrt ,kExprF64Add ,kExprF64Sub ,kExprF64Mul ,kExprF64Div ,kExprF64Min ,kExprF64Max ,kExprF64CopySign ,kExprI32ConvertI64 ,kExprI32SConvertF32 ,kExprI32UConvertF32 ,kExprI32SConvertF64 ,kExprI32UConvertF64 ,kExprI64SConvertI32 ,kExprI64UConvertI32 ,kExprI64SConvertF32 ,kExprI64UConvertF32 ,kExprI64SConvertF64 ,kExprI64UConvertF64 ,kExprF32SConvertI32 ,kExprF32UConvertI32 ,kExprF32SConvertI64 ,kExprF32UConvertI64 ,kExprF32ConvertF64 ,kExprF64SConvertI32 ,kExprF64UConvertI32 ,kExprF64SConvertI64 ,kExprF64UConvertI64 ,kExprF64ConvertF32 ,kExprI32ReinterpretF32 ,kExprI64ReinterpretF64 ,kExprF32ReinterpretI32 ,kExprF64ReinterpretI64];

var typeTable = [];
var funcTable = [];
var importFuncTable = [];
var importGlobalTable = [];
var hasMemory = false;
var hasTable = false;
var gExportCount = 0;
var gFuncCount = 0;
var gImportCount = 0;

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
                        constructType(builder, true) //addType(type)
                        break;
                case 5:
                        constructGlobal(builder) // addGlobal(local_type, mutable)
                        break;
                case 6:
                        constructFunction(builder) // addFunction(name, type)
                        break;
                case 7:
                        constructImport(builder)// addImport(module = "", name, type); addImportedGlobal(module = "", name, type); addImportedMemory(module = "", name, initial = 0, maximum); addImportedTable(module = "", name, initial, maximum)
                        break;
                case 8:
                        constructExport(builder) 
                        break;
        }
}