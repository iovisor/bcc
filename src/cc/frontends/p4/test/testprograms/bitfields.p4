header_type ht
{
  fields
  {
     f1 : 1;
     f2 : 2;
     f3 : 3;
     f4 : 4;
     f5 : 5;
     f6 : 6;
     f7 : 7;
     f8 : 8;
     f9 : 9;
     f10 : 10;
     f11 : 11;
     f12 : 12;
     f13 : 13;
     f14 : 14;
     f15 : 15;
     f16 : 16;
     f17 : 17;
     f18 : 18;
     f19 : 19;
     f20 : 20;
     f21 : 21;
     f22 : 22;
     f23 : 23;
     f24 : 24;
     f25 : 25;
     f26 : 26;
     f27 : 27;
     f28 : 28;
     f29 : 29;
     f30 : 30;
     f31 : 31;
     f32 : 32;
  }
}

header_type larget
{
  fields 
  {
    f48 : 48;
    f1: 1;
    f49 : 48;
    f2 : 1;
    f64 : 64;
    f3 : 1;
    f128 : 128;
  }
}

header ht h;
header larget large;

parser start
{
	extract(h);
	extract(large);
	return ingress;
}

control ingress
{
}
