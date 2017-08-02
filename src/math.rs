// Math module define polynomial types and operations that is used to setup the scheme.
use crypto;

pub struct Polynomial {
    pub elements: Vec<crypto::Scalar>,
}
impl Polynomial {
    /// generate a new polynomial of specific degree
    pub fn generate(degree: u32) -> Polynomial {
        let vec_size = degree + 1;
        let mut vec = Vec::with_capacity(vec_size as usize);

        for _ in 0..vec_size {
            let r = crypto::Scalar::generate();
            vec.push(r);
        }
        return Polynomial { elements: vec };
    }

    pub fn len(&self) -> usize {
        return self.elements.len();
    }

    /// get the value of a polynomial a0 + a1 * x^1 + a2 * x^2 + .. + an * x^n for a value x=at
    pub fn evaluate(&self, at: crypto::Scalar) -> crypto::Scalar {
        let mut r = crypto::Scalar::from_u32(0);
        for degree in 0..(self.elements.len()) {
            let v = self.elements[degree].clone();
            r = r + v * at.pow(degree as u32);
        }
        return r;
    }
    pub fn at_zero(&self) -> crypto::Scalar {
        return self.elements[0].clone();
    }
}
