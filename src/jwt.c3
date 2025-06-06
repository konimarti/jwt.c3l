// https://datatracker.ietf.org/doc/html/rfc7519
module jwt;

import std::collections::object;
import std::collections::map;

import std::encoding::base64;
import std::encoding::json;

import std::hash::sha256;

import std::io;

struct JsonWebToken (Printable)
{
	String base64_header;
	String base64_payload;
	String base64_signature;
}

enum JwtSigningMethod
{
	NONE,
	HS256
}

faultdef INVALID_JSON, INVALID_JWT_TYPE, ALGORITHM_NOT_IMPLEMENTED,
	INVALID_SIGNATURE;

fn String? decode(String text, String secret, Allocator allocator)
{
	JsonWebToken tok = parse(text)!;
	if (!tok.validate(secret)!) return INVALID_SIGNATURE?;
	return tok.payload(allocator);
}
fn String? new_decode(String text, String secret) => decode(text, secret, allocator::heap());
fn String? temp_decode(String text, String secret) => decode(text, secret, allocator::temp());

fn String? encode(String payload, String secret, JwtSigningMethod alg = HS256, Allocator allocator)
{
	JsonWebToken tok;
	@pool()
	{
		DString builder = dstring::temp(`{"alg":"`);
		switch (alg)
		{
			case NONE: builder.append("none");
			case HS256: builder.append("HS256");
			default: return ALGORITHM_NOT_IMPLEMENTED?;
		}
		builder.append(`","typ":"JWT"}`);
		tok.base64_header = urlencode(builder.str_view());
		tok.base64_payload = urlencode(payload);
		if (alg == HS256)
		{
			String input = string::tformat("%s.%s", tok.base64_header, tok.base64_payload);
			tok.base64_signature = urlencode(sha256::hmac(secret, input)[..]);
		}
		return string::format(allocator, "%s", tok);
	};
}
fn String? new_encode(String payload, String secret, JwtSigningMethod alg = HS256) => encode(payload, secret, alg, allocator::heap());
fn String? temp_encode(String payload, String secret, JwtSigningMethod alg = HS256) => encode(payload, secret, alg, allocator::temp());

fn JsonWebToken? parse(String text)
{
	JsonWebToken jwt;
	Splitter tokenizer = text.tokenize(".");
	if (try tok = tokenizer.next()) jwt.base64_header = tok;
	if (try tok = tokenizer.next()) jwt.base64_payload = tok;
	if (try tok = tokenizer.next()) jwt.base64_signature = tok;
	return jwt;
}

fn bool? JsonWebToken.validate(&self, String secret)
{
	@pool()
	{
		char[] json_text = urldecode(self.base64_header)!;

		Object* header = json::parse_string(allocator::temp(), (String)json_text)!;
		if (!header.is_map()) return INVALID_JSON?;
		if (header.get_string("typ")! != "JWT") return INVALID_JWT_TYPE?;
		String alg = header.get_string("alg")!;
		switch (alg)
		{
			case "HS256":
				String input = string::tformat("%s.%s", self.base64_header, self.base64_payload);
				char[] hmac = sha256::hmac(secret, input)[..];
				return self.base64_signature == urlencode(hmac);
			case "none": return true;
			case "NONE": return true;
			default: return ALGORITHM_NOT_IMPLEMENTED?;
		}
	};
}

fn String? JsonWebToken.header(&self, Allocator allocator) @inline => self.decode_base64(self.base64_header, allocator);
fn String? JsonWebToken.payload(&self, Allocator allocator) @inline => self.decode_base64(self.base64_payload, allocator);
fn String? JsonWebToken.decode_base64(&self, String base64url_encoded_json, Allocator allocator) @private
{
	@pool()
	{
		String json_text = (String)urldecode(base64url_encoded_json)!;
		return json_text.copy(allocator);
	};
}

fn usz? JsonWebToken.to_format(&self, Formatter *f) @dynamic => f.printf("%s.%s.%s", self.base64_header, self.base64_payload, self.base64_signature);

fn void? JsonWebToken.free(&self)
{
	*self = {};
}

fn String urlencode(char[] src, Allocator allocator = allocator::temp()) @inline @local
{
	return base64::encode(allocator: allocator, src: src, padding: base64::NO_PAD, alphabet: &base64::URL);
}

fn char[]? urldecode(String src, Allocator allocator = allocator::temp()) @inline @local
{
	return base64::decode(allocator: allocator, src: src, padding: base64::NO_PAD, alphabet: &base64::URL);
}
