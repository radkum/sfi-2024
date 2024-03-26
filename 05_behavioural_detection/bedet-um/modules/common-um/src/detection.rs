use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub struct DetectionReport {
    pub desc: String,
    pub cause: String,
}

impl Display for DetectionReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Detection {{ desc: \"{}\", cause: \"{}\" }}",
            self.desc, self.cause
        )
    }
}
