(module
	(func $add (param $lhs i32) (param $rhs i32) (result i32)
	      local.get $lhs
	      local.get $rhs
	      i32.add)
	(func $sub (param $lhs i32) (param $rhs i32) (result i32)
	      local.get $lhs
	      local.get $rhs
	      i32.sub
	      )
	(func $start (result i32)
	      (local i32 i32)
	      i32.const 0
              (if (result i32)
                (then 
		  i32.const 2
                  local.get 0
                  i32.sub
                  i32.const 0
                  i32.lt_s)
                (else
                  i32.const 0))
	      if
	        unreachable
	      end
	      i32.const 0
	      )

	(func $enter (result i32)
	      (call $start)
	      drop
	      (call $start)
	      )

	(export "start" (func $start))
	(export "_start" (func $enter))

	(export "add" (func $add))
	(export "sub" (func $sub)))

