module jwt_test @test;

import jwt;

const JWT_TEXT @local = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SP0R2USEDHqPV7mcIK08ZAs4WtPMQ0NdMHuSD8tnWOw";
const JWT_TEXT_NO_SIG @local = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
const SECRET @local = "1234";
const PAYLOAD = `{"sub":"1234567890","name":"John Doe","iat":1516239022}`;

fn void test_decode()
{
	String payload = jwt::new_decode(JWT_TEXT, SECRET)!!;
	defer payload.free(mem);
	assert(payload == `{"sub":"1234567890","name":"John Doe","iat":1516239022}`);
}

fn void test_decode_wrong_secret()
{
	String? payload = jwt::new_decode(JWT_TEXT, "bogus secret");
	assert(@catch(payload) == jwt::INVALID_SIGNATURE);
}

fn void test_encode()
{
	String token = jwt::new_encode(PAYLOAD, SECRET)!!;
	defer token.free(mem);
	assert(token == JWT_TEXT, "JWT encoding failed: got: %s, want: %s", token, JWT_TEXT);
}

fn void test_encode_no_sig()
{
	String token = jwt::new_encode(PAYLOAD, "", JwtSigningMethod.NONE)!!;
	defer token.free(mem);
	assert(token == JWT_TEXT_NO_SIG, "JWT encoding failed (no sig): got: %s, want: %s", token, JWT_TEXT_NO_SIG);
}

fn void test_parse()
{
	JsonWebToken tok = jwt::parse(JWT_TEXT)!!;
	assert(tok.base64_header == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
	assert(tok.base64_payload == "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
	assert(tok.base64_signature == "SP0R2USEDHqPV7mcIK08ZAs4WtPMQ0NdMHuSD8tnWOw");

	bool valid = tok.validate(SECRET)!!;
	assert(valid);
}

fn void test_parse_no_sig()
{
	JsonWebToken tok = jwt::parse(JWT_TEXT_NO_SIG)!!;
	assert(tok.base64_header == "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0");
	assert(tok.base64_payload == "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
	assert(tok.base64_signature == "");
}

