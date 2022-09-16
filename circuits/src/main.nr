use dep::std;

fn main(x: u32, y: pub u32, solnHash: pub Field) -> pub u32 {
    let z = x * y;
    let privSolnHash = std::hash::pedersen([x as Field, y as Field, z as Field]);
    constrain solnHash == privSolnHash[0];
    z
}
    