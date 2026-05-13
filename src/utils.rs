/*
 * mCaptcha - A proof of work based DoS protection system
 * Copyright © 2021 Aravinth Manivannan <realravinth@batsense.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// utility function to get a randomly generated string
// of size len
pub fn get_random(len: usize) -> String {
    use std::iter;

    use rand::distr::Alphanumeric;
    use rand::{rng, Rng};

    let mut rng = rng();

    iter::repeat(())
        .map(|()| rng.sample(Alphanumeric) as char)
        .take(len)
        .collect::<String>()
}
