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
	      i32.const 1
              (if (result i32)
                (then 
		  i32.const 2
                  local.get 0
                  i32.sub
                  i32.const 0
                  i32.lt_s)
                (else
                  unreachable))
	      if
	        unreachable
	      end
	      i32.const 0
	      )
	(export "_start" (func $start))
	(export "add" (func $add))
	(export "sub" (func $sub)))

