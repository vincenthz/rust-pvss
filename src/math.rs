// Math module define polynomial types and operations that is used to setup the scheme.
use super::crypto;
use super::crypto::EcOperation;

#[derive(Clone)]
pub struct Polynomial<C: EcOperation> {
    pub elements: Vec<crypto::Scalar<C>>,
}

impl<C: EcOperation> Polynomial<C> {
    /// generate a new polynomial of specific degree
    pub fn generate(drg: &mut crypto::Drg, degree: u32) -> Polynomial<C> {
        let vec_size = degree + 1;
        let mut vec = Vec::with_capacity(vec_size as usize);

        for _ in 0..vec_size {
            let r = crypto::Scalar::generate(drg);
            vec.push(r)
        }
        Polynomial { elements: vec }
    }

    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// get the value of a polynomial a0 + a1 * x^1 + a2 * x^2 + .. + an * x^n for a value x=at
    pub fn evaluate(&self, at: crypto::Scalar<C>) -> crypto::Scalar<C> {
        let mut r = crypto::Scalar::from_u32(0);
        for degree in 0..(self.elements.len()) {
            let v = &self.elements[degree];
            r = r + v * &at.pow(degree as u32);
        }
        r
    }
    pub fn at_zero(&self) -> &crypto::Scalar<C> {
        &self.elements[0]
    }
}
