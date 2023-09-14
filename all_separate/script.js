var form = document.getElementById('registrationForm');
var emailInput = document.getElementById('email');
const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;

form.addEventListener('submit', function(event) {
  var name = document.getElementById('name').value;
  var email = emailInput.value;
  var dob = document.getElementById('dob').value;
  var gender = document.querySelector('input[name="gender"]:checked');
  var mobile = document.getElementById('mobile').value;
  var pincode = document.getElementById('pincode').value;
  var country = document.getElementById('country').value;
  var pin = document.getElementById('pincode');

  if (!name || !email || !dob || !gender || !mobile || !pincode || !country) {
    event.preventDefault();
    alert('Please fill in all fields.');
  } else if (!emailRegex.test(email)) {
    event.preventDefault();
    alert('Please enter a valid email address.');
  } else if (country === 'India') {
    event.preventDefault();
    pin.setAttribute("maxlength", "6");
  } else if ((country === 'USA' || country === 'Canada')) {
    event.preventDefault();
    pin.setAttribute("maxlength", "4");
  }
});