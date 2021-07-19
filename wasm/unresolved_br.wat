
(module
	(func $add (param $lhs i32) (param $rhs i32) (result i32)
	      local.get $lhs
	      local.get $rhs
	      i32.add)
	(func $sub (param $lhs i32) (param $rhs i32) (result i32)
	      local.get $lhs
	      local.get $rhs
	      i32.sub
	      block
		local.get 0
		i32.const 1
		i32.add
		block
		  block
		    br 1
		  end
		end
		local.set 0
		local.get 0
		i32.const 4
		i32.gt_u
		br_if 0
	      end
	      )
	(func $start (result i32)
	      (local i32 i32)
	      i32.const 0
	      i32.const 1
	      call $sub
	      )
	(export "start" (func $start))
	(export "add" (func $add))
	(export "sub" (func $sub)))
