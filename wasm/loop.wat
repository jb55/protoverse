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
	      local.set 0
	      block
	        loop
	          local.get 0
		  i32.const 1
		  i32.add
		  local.set 0
	          i32.const 4
		  local.get 0
	          i32.gt_u
	          br_if 0
	        end
	      end
	      i32.const 0
	      )
	(export "start" (func $start))
	(export "add" (func $add))
	(export "sub" (func $sub)))
