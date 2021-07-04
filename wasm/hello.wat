(module
	(func $add (param $lhs i32) (param $rhs i32) (result i32)
	      local.get $lhs
	      local.get $rhs
	      i32.add)
	(func $start (result i32)
	      (local i32 i32)
	      i32.const 65537
	      local.set 0
	      local.get 0
	      i32.const 2
	      call $add)
	(export "start" (func $start))
	(export "add" (func $add)))
