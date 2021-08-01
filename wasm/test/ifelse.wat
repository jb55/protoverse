(module
  (memory $mem 0)
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
	          local.get 0
		  i32.const 1
		  i32.add
		  local.set 0
	          i32.const 4
		  local.get 0
	          i32.gt_u
	          if
		    nop
		    br 0
		    if
		      nop
		    else
		      nop
		    end
		  else
		    unreachable
		    block
		      nop
		    end
		  end
	      end
	      i32.const 0
	      )

	(func $enter (result i32)
	      (local i32)
	      (call $start)
	      local.set 0
	      (call $start)
	      local.get 0
	      i32.ne
	      )

	(export "start" (func $start))
	(export "_start" (func $enter))

	(export "add" (func $add))
	(export "memory" (memory $mem))
	(export "sub" (func $sub)))
