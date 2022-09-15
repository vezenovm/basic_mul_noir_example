// Test unsafe integer multiplication with overflow: 12^8 = 429 981 696
// The circuit should handle properly the growth of the bit size
fn main(mut x: u32, y: pub u32, z: pub u32) -> pub [u32; 2] {
    x = x * y;
    x = x * x;  //144
    x = x * x;  //20736
    //x = x * x;  //429 981 696
    constrain x == z;
    x = x * 2;
    [x, z]
}
    